#!/usr/bin/env python3
# Display name: AI drawing
# 显示名称：AI 生图
# Description: Draw a picture from a text prompt with the configured image model, optionally starting from reference images. The image is saved into the user's Pictures (the script cache where Pictures is not given) and attached for you to see.
# 描述：照文字画一张图，可以带参考图；存进用户的图片目录（没有的会话存进脚本缓存），附上给 AI 看，要给人看用 show。
# Timeout: 300
# Parameters:
# {"type": "object", "properties": {
#   "prompt": {"type": "string", "description": "What to draw."},
#   "reference_images": {"type": "array", "items": {"type": "string"}, "description": "Images to draw from, at most 8: local file paths or http(s) URLs."},
#   "aspect_ratio": {"type": "string", "enum": ["auto", "1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9"], "description": "Default: the one set for this package."},
#   "resolution": {"type": "string", "enum": ["1K", "2K", "4K"], "description": "Only RightCode draws above 1K. Default: the one set for this package."}
# }, "required": ["prompt"]}
import base64
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_REFERENCES = 8
MAX_REFERENCE_BYTES = 20 << 20
# 2048×2048 的 PNG 常见 3-8 MB，留四倍余量；图在哪由服务说了算，不设上限就是对面说多少收多少
MAX_RESULT_BYTES = 32 << 20
MAX_ERROR_BYTES = 64 << 10
REFERENCE_TIMEOUT = 20
ATTACH_BYTES = 5 << 20
ATTACH_SIDE = 8000
KEEP_CACHED = 20

ASPECTS = ("auto", "1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9")
RESOLUTIONS = ("1K", "2K", "4K")

# Proxies in fake-IP mode (Clash and friends) answer every name from this range.
FAKE_IP = ipaddress.ip_network("198.18.0.0/15")

# RightCode 的尺寸表：2K、4K 都是长边 2048
RIGHTCODE_SIZES = {
    "1:1": ("1024x1024", "2048x2048"),
    "3:2": ("1536x1024", "2048x1365"),
    "16:9": ("1536x864", "2048x1152"),
    "4:3": ("1365x1024", "2048x1536"),
    "5:4": ("1280x1024", "2048x1638"),
    "21:9": ("1536x658", "2048x878"),
    "2:3": ("1024x1536", "1365x2048"),
    "3:4": ("1024x1365", "1536x2048"),
    "9:16": ("864x1536", "1152x2048"),
    "4:5": ("1024x1280", "1638x2048"),
}
PORTRAIT = ("2:3", "3:4", "9:16", "4:5")
LANDSCAPE = ("3:2", "16:9", "4:3", "5:4", "21:9")


def fail(message):
    print(f"错误：{message}")
    sys.exit(1)


def progress(text):
    print(f"miyu-progress: {text}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# settings: the package's own items, final values, read at call time
# --------------------------------------------------------------------------

def load_settings():
    raw = os.environ.get("MIYU_SETTINGS_JSON")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        fail("MIYU_SETTINGS_JSON 不是 JSON")
    return value if isinstance(value, dict) else {}


def text_setting(settings, key, default=""):
    value = settings.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else default


def endpoint(base_url, path):
    """Append /v1 unless the address already ends in a version segment."""
    base = base_url.rstrip("/")
    if not re.search(r"/v\d+[a-z]*$", urllib.parse.urlsplit(base).path):
        base += "/v1"
    return f"{base}/{path}"


def is_rightcode(base_url):
    host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
    return host == "right.codes" or host.endswith(".right.codes")


def is_gpt_image(model):
    return "gpt-image" in model.lower()


# --------------------------------------------------------------------------
# network: references and returned images only from public addresses
# --------------------------------------------------------------------------

def public_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return False
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global and address not in FAKE_IP:
            return False
    return bool(infos)


class GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_url(newurl):
            raise urllib.error.URLError(f"redirect to a non-public address: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


GUARDED = urllib.request.build_opener(GuardedRedirect)
# 接口地址是管理员填的，可以是本机的中转，不查公网
DIRECT = urllib.request.build_opener()


def read_capped(response, limit):
    length = response.headers.get("Content-Length")
    if length and length.isdigit() and int(length) > limit:
        raise ValueError(f"larger than {limit >> 20} MiB")
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"larger than {limit >> 20} MiB")
    return data


def download(url, limit, timeout, trusted_host=""):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    opener = DIRECT if trusted_host and host == trusted_host else GUARDED
    if opener is GUARDED and not public_url(url):
        raise urllib.error.URLError(f"not a public address: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "miyu-ai-draw/0.1", "Accept": "image/*"})
    with opener.open(request, timeout=timeout) as response:
        return read_capped(response, limit)


# --------------------------------------------------------------------------
# image bytes: type and size from the header only
# --------------------------------------------------------------------------

def sniff(data):
    """Return (mime, width, height) for PNG/JPEG/GIF/WebP, or None."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return "image/png", w, h
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return "image/gif", w, h
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8 ":
            w, h = struct.unpack("<HH", data[26:30])
            return "image/webp", w & 0x3FFF, h & 0x3FFF
        if chunk == b"VP8L":
            b = data[21:25]
            w = 1 + (((b[1] & 0x3F) << 8) | b[0])
            h = 1 + (((b[3] & 0x0F) << 10) | (b[2] << 2) | ((b[1] & 0xC0) >> 6))
            return "image/webp", w, h
        if chunk == b"VP8X":
            w = 1 + int.from_bytes(data[24:27], "little")
            h = 1 + int.from_bytes(data[27:30], "little")
            return "image/webp", w, h
        return None
    if data[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", data[i + 5:i + 9])
                return "image/jpeg", w, h
            i += 2 + length
        return None
    return None


EXT = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp"}
REFERENCE_TYPES = ("image/png", "image/jpeg", "image/webp")


# --------------------------------------------------------------------------
# reference images
# --------------------------------------------------------------------------

def reference_list(value):
    """Take the shapes models actually send: an array, one string, or a JSON array inside a string."""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                fail(f"reference_images 不是合法的 JSON：{text[:200]}")
        else:
            return [text]
    if not isinstance(value, list):
        fail("reference_images 要是路径或网址的数组")
    out = []
    for item in value:
        if not isinstance(item, str):
            fail(f"reference_images 里的每一项要是字符串，这一项是 {json.dumps(item, ensure_ascii=False)[:100]}")
        if item.strip():
            out.append(item.strip())
    if value and not out:
        fail("reference_images 给了，但里面没有一个能用的路径或网址")
    return out


def load_reference(ref):
    """Return (bytes, mime) for one reference, or fail with why."""
    if ref.startswith(("http://", "https://")):
        try:
            data = download(ref, MAX_REFERENCE_BYTES, REFERENCE_TIMEOUT)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            fail(f"参考图下不下来：{ref}（{exc}）")
    else:
        path = os.path.expanduser(ref)
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_REFERENCE_BYTES + 1)
        except OSError as exc:
            fail(f"参考图读不了：{ref}（{exc.strerror or exc}）")
        if len(data) > MAX_REFERENCE_BYTES:
            fail(f"参考图超过 {MAX_REFERENCE_BYTES >> 20} MiB：{ref}")
    info = sniff(data)
    if not info or info[0] not in REFERENCE_TYPES:
        fail(f"参考图要是 PNG、JPEG 或 WebP：{ref}")
    return data, info[0]


# --------------------------------------------------------------------------
# request
# --------------------------------------------------------------------------

def resolve_size(fixed, rightcode, model, aspect, resolution):
    if fixed:
        return fixed
    if rightcode:
        pair = RIGHTCODE_SIZES.get(aspect)
        return pair and pair[0 if resolution == "1K" else 1]
    if is_gpt_image(model):
        if aspect == "1:1":
            return "1024x1024"
        return "1024x1536" if aspect in PORTRAIT else "1536x1024" if aspect in LANDSCAPE else "auto"
    return "1024x1792" if aspect in PORTRAIT else "1792x1024" if aspect in LANDSCAPE else "1024x1024"


def multipart(fields, files):
    boundary = f"----miyu{uuid.uuid4().hex}"
    out = bytearray()
    for name, value in fields.items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                f"{value}\r\n").encode()
    for index, (data, mime) in enumerate(files, 1):
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"image[]\"; "
                f"filename=\"reference-{index}.{EXT[mime]}\"\r\nContent-Type: {mime}\r\n\r\n").encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def build_request(settings, prompt, aspect, resolution, references):
    base_url = text_setting(settings, "base_url", "https://api.openai.com/v1")
    model = text_setting(settings, "model", "gpt-image-1")
    rightcode = is_rightcode(base_url)
    gpt_image = is_gpt_image(model)
    fields = {"model": model, "prompt": prompt, "n": 1}
    size = resolve_size(text_setting(settings, "size"), rightcode, model, aspect, resolution)
    if size:
        fields["size"] = size
    quality = text_setting(settings, "quality", "auto")
    if quality != "auto":
        fields["quality"] = quality
    if gpt_image:
        output_format = text_setting(settings, "output_format", "png")
        if output_format != "png":
            fields["output_format"] = output_format
        background = text_setting(settings, "background", "auto")
        if background != "auto":
            fields["background"] = background
    headers = {"Authorization": f"Bearer {text_setting(settings, 'api_key')}", "User-Agent": "miyu-ai-draw/0.1"}

    if rightcode:
        # RightCode：参考图以 base64 数组放进 generations 的 JSON；带参考图时它交回网址
        if aspect != "auto":
            fields["aspect_ratio"] = aspect
        if references:
            fields["image"] = [base64.b64encode(data).decode() for data, _ in references]
            fields["response_format"] = "url"
        body = json.dumps(fields, ensure_ascii=False).encode()
        headers["Content-Type"] = "application/json"
        return endpoint(base_url, "images/generations"), body, headers
    if references:
        # OpenAI：参考图走 edits，multipart，字段名 image[]
        body, headers["Content-Type"] = multipart(fields, references)
        return endpoint(base_url, "images/edits"), body, headers
    if gpt_image:
        if text_setting(settings, "moderation", "auto") != "auto":
            fields["moderation"] = text_setting(settings, "moderation")
    else:
        # DALL·E 这类默认交网址，要它直接交图
        fields["response_format"] = "b64_json"
    headers["Content-Type"] = "application/json"
    return endpoint(base_url, "images/generations"), json.dumps(fields, ensure_ascii=False).encode(), headers


def error_text(body, key):
    text = body.decode("utf-8", "replace")
    try:
        detail = json.loads(text).get("error")
        if isinstance(detail, dict):
            text = detail.get("message") or text
        elif isinstance(detail, str):
            text = detail
    except (json.JSONDecodeError, AttributeError):
        pass
    text = " ".join(text.split())
    if key:
        text = text.replace(key, "***")
    return text[:500] + ("…" if len(text) > 500 else "")


def call_api(url, body, headers, timeout, key):
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with DIRECT.open(request, timeout=timeout) as response:
            return read_capped(response, MAX_RESULT_BYTES * 2)
    except urllib.error.HTTPError as exc:
        try:
            detail = error_text(exc.read(MAX_ERROR_BYTES), key)
        except OSError:
            detail = ""
        fail(f"生图接口回了 {exc.code}：{detail or exc.reason}")
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None) or exc
        if isinstance(reason, TimeoutError):
            fail(f"等了 {timeout} 秒还没画完。画质、尺寸调低些，或者在软件包页把超时调长")
        fail(f"连不上生图接口 {urllib.parse.urlsplit(url).netloc}：{reason}")


def extract_image(raw, base_host, timeout):
    try:
        response = json.loads(raw)
    except json.JSONDecodeError:
        fail(f"生图接口交回的不是 JSON：{' '.join(raw[:200].decode('utf-8', 'replace').split())}")
    items = response.get("data") if isinstance(response, dict) else None
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        fail(f"生图接口交回的里面没有图：{json.dumps(response, ensure_ascii=False)[:300]}")
    first = items[0]
    revised = first.get("revised_prompt") if isinstance(first.get("revised_prompt"), str) else ""
    if isinstance(first.get("b64_json"), str):
        try:
            return base64.b64decode(first["b64_json"], validate=True), revised
        except ValueError:
            fail("生图接口交回的 b64_json 解不开")
    if isinstance(first.get("url"), str):
        progress("downloading the image")
        try:
            return download(first["url"], MAX_RESULT_BYTES, timeout, trusted_host=base_host), revised
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            fail(f"图画好了，但下不下来：{exc}")
    fail("生图接口交回的里面既没有 b64_json 也没有 url")


# --------------------------------------------------------------------------

def slug(prompt):
    kept = "".join(ch if ch.isalnum() else "-" for ch in prompt.strip())
    kept = re.sub(r"-+", "-", kept).strip("-")
    return kept[:24] or "image"


def human(size):
    return f"{size / 1024:.0f} KiB" if size < 1 << 20 else f"{size / (1 << 20):.1f} MiB"


def prune(root, keep):
    """Keep only the newest `keep` images in the cache."""
    try:
        entries = [e for e in os.scandir(root) if e.is_file(follow_symlinks=False)]
    except OSError:
        return
    entries.sort(key=lambda e: e.stat(follow_symlinks=False).st_mtime, reverse=True)
    for entry in entries[keep:]:
        try:
            os.remove(entry.path)
        except OSError:
            pass


def main():
    try:
        args = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        fail(f"参数不是 JSON：{exc}")
    if not isinstance(args, dict):
        fail("参数要是一个 JSON 对象")
    settings = load_settings()
    key = text_setting(settings, "api_key")
    if not key:
        fail("还没填 API Key：在设置的「软件包」页找「AI 生图」，填接口地址和 API Key")

    prompt = str(args.get("prompt") or "").strip()
    if not prompt:
        fail("prompt 是空的：要画什么")
    aspect = str(args.get("aspect_ratio") or text_setting(settings, "aspect_ratio", "auto")).strip()
    if aspect not in ASPECTS:
        fail(f"aspect_ratio 只认 {'、'.join(ASPECTS)}")
    resolution = str(args.get("resolution") or text_setting(settings, "resolution", "1K")).strip().upper()
    if resolution not in RESOLUTIONS:
        fail(f"resolution 只认 {'、'.join(RESOLUTIONS)}")
    refs = reference_list(args.get("reference_images"))
    if len(refs) > MAX_REFERENCES:
        fail(f"参考图最多 {MAX_REFERENCES} 张，给了 {len(refs)} 张")
    references = [load_reference(ref) for ref in refs]

    timeout = settings.get("timeout")
    timeout = timeout if isinstance(timeout, int) and not isinstance(timeout, bool) and 30 <= timeout <= 280 else 240
    url, body, headers = build_request(settings, prompt, aspect, resolution, references)
    progress(f"drawing with {text_setting(settings, 'model', 'gpt-image-1')}")
    started = time.monotonic()
    raw = call_api(url, body, headers, timeout, key)
    data, revised = extract_image(raw, (urllib.parse.urlsplit(url).hostname or "").lower(), timeout)
    elapsed = time.monotonic() - started
    info = sniff(data)
    if not info:
        fail("生图接口交回的不是认得的图片（PNG、JPEG、GIF、WebP）")
    mime, width, height = info

    # 本机会话给用户的图片目录，存了就是人的；群里这类会话没有，退回缓存、只留最近几张
    pictures = os.environ.get("MIYU_PICTURES_DIR")
    base = pictures or os.environ.get("MIYU_SCRIPT_CACHE_DIR")
    if not base:
        fail("没有图片目录也没有脚本缓存目录（MIYU_PICTURES_DIR、MIYU_SCRIPT_CACHE_DIR），要在 Miyu 里调")
    folder = os.path.join(base, "AI生图" if pictures else "images")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        fail(f"建不了 {folder}：{exc}")
    stem = os.path.join(folder, f"{time.strftime('%Y%m%d-%H%M%S')}-{slug(prompt)}")
    path, number = f"{stem}.{EXT[mime]}", 1
    while os.path.lexists(path):
        number += 1
        path = f"{stem}-{number}.{EXT[mime]}"
    try:
        with open(path, "xb") as fh:
            fh.write(data)
    except OSError as exc:
        fail(f"图画好了，但存不进 {path}：{exc}")
    if not pictures:
        prune(folder, keep=KEEP_CACHED)

    attach_dir = os.environ.get("MIYU_SCRIPT_IMAGES_DIR")
    attached = bool(attach_dir) and len(data) <= ATTACH_BYTES and max(width, height) <= ATTACH_SIDE
    if attached:
        shutil.copy(path, os.path.join(attach_dir, os.path.basename(path)))

    out = [f"画好了，存在 `{path}` — {width}×{height} {EXT[mime].upper()} {human(len(data))}，用了 {elapsed:.0f} 秒。"]
    if references:
        out.append(f"照 {len(references)} 张参考图画的。")
    if revised and revised != prompt:
        out.append(f"服务改写后的提示词：{revised}")
    if attached:
        out.append("图附在后面给你看。")
    else:
        out.append("没有附图给你看（图超过 5 MiB 或这里收不了图）。")
    if pictures:
        out.append("要给用户看，用 show 工具打开这个路径。图存在用户的图片目录里；用户不要的，删掉就行。")
    else:
        out.append(f"要给用户看，用 show 工具打开这个路径。图在缓存里，只留最近 {KEEP_CACHED} 张；用户要留的，拷到工作区或用户说的地方。")
    print("\n".join(out))


if __name__ == "__main__":
    main()
