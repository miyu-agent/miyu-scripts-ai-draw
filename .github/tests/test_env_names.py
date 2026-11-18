# ai_draw.py 读新环境变量名的测试（审计 2026-11-18 #168）。
#
# 跑法（在仓库根）：
#   python3 -I -B -m unittest discover -s .github/tests
# （不加 -t .：.github 不是合法的包名，加了 unittest 会报 Start directory is not importable。）
#
# 只用标准库；不联网：call_api 换成桩，交回构造的 PNG，断网也能跑。HOME、XDG_*、MIYU_* 都指到临时目录。
# 放在 .github/tests/ 而不是 tests/：打包会跳过 .github，测试不会进包。

import base64
import importlib.util
import io
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "ai_draw.py"

# 64×48 的 PNG 头：sniff 只看前 24 字节
PNG = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 64, 48) + b"\x08\x06\x00\x00\x00"


def load():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("ai_draw_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sandbox(unittest.TestCase):
    """每条测试一个临时目录，环境里去掉所有 MIYU_*，生图接口换成交回固定 PNG 的桩。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("MIYU_", "XDG_"))}
        env.update(HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "cfg"),
                   XDG_CACHE_HOME=str(root / "xdg-cache"), XDG_STATE_HOME=str(root / "xdg-state"),
                   XDG_DATA_HOME=str(root / "xdg-data"),
                   MIYU_SETTINGS_JSON=json.dumps({"api_key": "sk-test", "base_url": "https://api.example.invalid/v1"}))
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = root
        self.mod = load()
        self.calls = []

        def fake_call_api(url, body, headers, timeout, key):
            self.calls.append(url)
            return json.dumps({"data": [{"b64_json": base64.b64encode(PNG).decode()}]}).encode()

        self.mod.call_api = fake_call_api

    def call(self, args):
        """照 main() 跑一次：stdin 喂 JSON，返回 (退出码, 输出)。"""
        out = io.StringIO()
        code = 0
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(args))), redirect_stdout(out), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            try:
                self.mod.main()
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue()


class EnvNames(Sandbox):
    # 审计 #168：核心 FH-6 以后只给新名字 MIYU_CACHE_DIR、MIYU_IMAGES_DIR，不再给 MIYU_SCRIPT_*。
    # 脚本两处只读旧名：没有图片目录时退回的缓存目录、交图给 AI 看的附图目录。

    def test_cache_dir_new_name(self):
        # 没有 MIYU_PICTURES_DIR 的会话，图应存进 MIYU_CACHE_DIR/images。现在读不到，报「没有图片目录也没有脚本缓存目录」。
        cache = self.root / "cache"
        cache.mkdir()
        os.environ["MIYU_CACHE_DIR"] = str(cache)
        self.assertNotIn("MIYU_SCRIPT_CACHE_DIR", os.environ)
        code, out = self.call({"prompt": "一只猫"})
        self.assertEqual(code, 0, out)
        saved = list((cache / "images").glob("*.png")) if (cache / "images").is_dir() else []
        self.assertEqual(len(saved), 1, f"MIYU_CACHE_DIR/images 里没有画好的图：{out}")

    def test_images_dir_new_name(self):
        # 图应复制一份进 MIYU_IMAGES_DIR 给 AI 看。现在读不到，输出「没有附图给你看」，目录是空的。
        pictures = self.root / "pictures"
        images = self.root / "attach"
        pictures.mkdir()
        images.mkdir()
        os.environ["MIYU_PICTURES_DIR"] = str(pictures)
        os.environ["MIYU_IMAGES_DIR"] = str(images)
        self.assertNotIn("MIYU_SCRIPT_IMAGES_DIR", os.environ)
        code, out = self.call({"prompt": "一只猫"})
        self.assertEqual(code, 0, out)
        self.assertEqual(len(list(images.glob("*.png"))), 1, f"MIYU_IMAGES_DIR 里没有附图：{out}")
        self.assertIn("图附在后面给你看", out)


if __name__ == "__main__":
    unittest.main()
