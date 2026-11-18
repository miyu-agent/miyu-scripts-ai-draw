# ai_draw.py 的测试（审计 2026-11-18）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库；不联网（只测纯函数 sniff），断网也能跑。HOME、XDG_*、MIYU_* 都指到临时目录。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import importlib.util
import io
import ipaddress
import os
import pathlib
import socket
import ssl
import struct
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "ai_draw.py"

# SOF0 段：长度 11、8 位、高 200、宽 100、1 个分量
SOF0 = struct.pack(">HBHHB", 11, 8, 200, 100, 1) + b"\x01\x11\x00"


def load():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("ai_draw_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sandbox(unittest.TestCase):
    """每条测试一个临时目录，环境里去掉所有 MIYU_*。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MIYU_", "XDG_"))}
        env.update(HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "cfg"),
                   XDG_CACHE_HOME=str(root / "xdg-cache"), XDG_STATE_HOME=str(root / "xdg-state"),
                   XDG_DATA_HOME=str(root / "xdg-data"))
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = root
        self.mod = load()


class SniffJpegFill(Sandbox):
    # 审计 #173-d：JPEG 的 marker 前可以有任意个 0xFF 填充字节（ITU T.81 B.1.1.2）。
    # sniff 在 0xFF 后直接把下一个字节当 marker，遇到 FF FF C0 就把 0xFF 当段、按后两字节当长度跳走，合法图判成 None。
    def test_fill_byte_before_sof0(self):
        data = b"\xff\xd8" + b"\xff\xff\xc0" + SOF0 + b"\xff\xd9"
        self.assertEqual(self.mod.sniff(data), ("image/jpeg", 100, 200))

    # 防改坏（现在就绿）：不带填充字节的照旧认得。
    def test_plain_sof0(self):
        data = b"\xff\xd8" + b"\xff\xc0" + SOF0 + b"\xff\xd9"
        self.assertEqual(self.mod.sniff(data), ("image/jpeg", 100, 200))


class FakeNet:
    """桩掉解析和建连接：answers 是每个主机名依次回的地址（用完了就一直回最后一个），
    responses 是每条连接依次交回的原始 HTTP 回应。connected 记下每次真正去连的地址。"""

    def __init__(self, answers, responses):
        self.answers = {host: list(addrs) for host, addrs in answers.items()}
        self.responses = list(responses)
        self.lookups = []
        self.connected = []
        self.server_names = []
        net = self

        class FakeSocket:
            def __init__(self, *args, **kwargs):
                self.reply = b""

            def connect(self, address):
                net.connected.append(address[:2])
                self.reply = net.responses.pop(0) if net.responses else b""

            def makefile(self, *args, **kwargs):
                return io.BytesIO(self.reply)

            def settimeout(self, *args):
                pass

            def setsockopt(self, *args):
                pass

            def sendall(self, data):
                pass

            def close(self):
                pass

        self.socket_class = FakeSocket

    def getaddrinfo(self, host, port, *args, **kwargs):
        try:
            ipaddress.ip_address(host)
            address = host
        except ValueError:
            self.lookups.append(host)
            queue = self.answers[host]
            address = queue.pop(0) if len(queue) > 1 else queue[0]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 80))]

    def wrap_socket(self, context, sock, server_hostname=None, **kwargs):
        self.server_names.append(server_hostname)
        return sock

    def patches(self):
        return [mock.patch("socket.getaddrinfo", self.getaddrinfo),
                mock.patch("socket.socket", self.socket_class),
                mock.patch.object(ssl.SSLContext, "wrap_socket",
                                  lambda context, sock, **kw: self.wrap_socket(context, sock, **kw))]


def ok_response(body=b"ok"):
    return b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)


class PinnedAddress(Sandbox):
    # 审计 #173-e：public_url() 先 getaddrinfo 判公网，之后 urlopen 自己再解析一次。
    # 攻击者控制一个短 TTL 的域名，第一次回公网、第二次回 127.0.0.1，查过的和连的就不是同一个地址。
    # 断言行为：解析被换了以后，连的仍是查过的公网地址或者干脆不连，绝不是 127.0.0.1。

    def setUp(self):
        super().setUp()
        for name in [k for k in os.environ if k.lower().endswith("_proxy")]:
            del os.environ[name]

    def fetch(self, net, url, env=None):
        os.environ.update(env or {})
        mod = load()
        for patcher in net.patches():
            patcher.start()
            self.addCleanup(patcher.stop)
        return mod.download(url, 1 << 20, 5)

    def test_rebound_dns_never_connects_loopback(self):
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                net = FakeNet({"rebind.example": ["93.184.216.34", "127.0.0.1"]}, [ok_response()])
                try:
                    self.fetch(net, f"{scheme}://rebind.example/x.png")
                except urllib.error.URLError:
                    pass
                self.assertNotIn("127.0.0.1", [address[0] for address in net.connected])

    # 防改坏：公网地址照常取到内容；HTTPS 的 SNI（和证书核对）仍用原主机名。
    def test_public_address_fetches(self):
        net = FakeNet({"img.example": ["93.184.216.34"]}, [ok_response()])
        self.assertEqual(self.fetch(net, "http://img.example/x.png"), b"ok")
        self.assertEqual(net.connected, [("93.184.216.34", 80)])
        net = FakeNet({"img.example": ["93.184.216.34"]}, [ok_response()])
        self.assertEqual(self.fetch(net, "https://img.example/x.png"), b"ok")
        self.assertEqual(net.connected, [("93.184.216.34", 443)])
        self.assertEqual(net.server_names, ["img.example"])

    # 防改坏：内网地址照旧被拒，一次都不连。
    def test_private_address_refused(self):
        net = FakeNet({"inner.example": ["10.0.0.1"]}, [ok_response()])
        with self.assertRaisesRegex(urllib.error.URLError, "not a public address"):
            self.fetch(net, "http://inner.example/x.png")
        self.assertEqual(net.connected, [])

    # 防改坏：跳转到内网照旧被拒，只连过第一跳的公网地址。
    def test_redirect_to_private_refused(self):
        redirect = b"HTTP/1.1 302 Found\r\nLocation: http://inner.example/x.png\r\nContent-Length: 0\r\n\r\n"
        net = FakeNet({"img.example": ["93.184.216.34"], "inner.example": ["192.168.1.1"]},
                      [redirect, ok_response()])
        with self.assertRaisesRegex(urllib.error.URLError, "redirect to a non-public address"):
            self.fetch(net, "http://img.example/x.png")
        self.assertEqual(net.connected, [("93.184.216.34", 80)])

    # 防改坏：设了代理就连代理（本机的代理也行），目标在代理的假 IP 段 198.18.0.0/15 照旧放行。
    def test_proxy_connects_to_proxy(self):
        net = FakeNet({"img.example": ["198.18.0.5"]}, [ok_response()])
        data = self.fetch(net, "http://img.example/x.png", env={"http_proxy": "http://127.0.0.1:7890"})
        self.assertEqual(data, b"ok")
        self.assertEqual(net.connected, [("127.0.0.1", 7890)])


if __name__ == "__main__":
    unittest.main()


class RightCodeAddress(unittest.TestCase):
    """RightCode 换了域名（2026-11）：新旧地址都走 RightCode 那套，别家的不算。"""

    def setUp(self):
        self.mod = load()

    def test_new_api_address(self):
        self.assertTrue(self.mod.is_rightcode("https://api.site/draw"))

    def test_old_addresses(self):
        for url in ("https://www.right.codes/draw", "https://right.codes/draw", "https://rightapi.ai/draw"):
            self.assertTrue(self.mod.is_rightcode(url), url)

    def test_others_are_not(self):
        for url in ("https://api.openai.com/v1", "https://evil-api.site/draw", "https://api.site.example.com/draw"):
            self.assertFalse(self.mod.is_rightcode(url), url)
