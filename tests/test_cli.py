from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from payload_server import cli


class ServerStateTests(unittest.TestCase):
    def test_from_legacy_env_migrates_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            serve_dir = Path(tmpdir) / "payloads"
            serve_dir.mkdir()
            raw = "\n".join(
                [
                    "MODE=linux",
                    "LHOST=10.10.14.5",
                    "HTTP_PORT=8001",
                    "SHELL_PORT=4444",
                    "ENABLE_SMB=1",
                    "HTTP_BACKEND=fuzzy",
                    f"PAYLOAD_ROOT={tmpdir}",
                    f"SERVE_DIR={serve_dir}",
                    "BASE_URL=http://10.10.14.5:8001",
                    "SMB_SHARE_NAME=PAYLOADS",
                    r"SMB_UNC=\\10.10.14.5\PAYLOADS",
                ]
            )
            state_path = Path(tmpdir) / "state.env"
            state_path.write_text(raw, encoding="utf-8")

            state = cli.ServerState.from_path(state_path)

            self.assertEqual(state.mode, "linux")
            self.assertEqual(state.http_port, 8001)
            self.assertTrue(state.enable_smb)
            self.assertEqual(state.serve_dir, str(serve_dir))

    def test_save_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = cli.ServerState(
                mode="windows",
                lhost="10.0.0.1",
                http_port=8000,
                shell_port=443,
                enable_smb=False,
                http_backend="fuzzy",
                payload_root=tmpdir,
                serve_dir=tmpdir,
                base_url="http://10.0.0.1:8000",
                smb_share_name="PAYLOADS",
                smb_unc="",
            )
            state_path = Path(tmpdir) / "state.json"
            state.save(state_path)

            written = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(written["mode"], "windows")
            self.assertEqual(written["http_port"], 8000)


class HelperTests(unittest.TestCase):
    def test_http_url_for_relative_quotes_path(self) -> None:
        result = cli.http_url_for_relative("http://127.0.0.1:8000", "bin/My Tool.exe")
        self.assertEqual(result, "http://127.0.0.1:8000/bin/My%20Tool.exe")

    def test_fuzzy_translate_matches_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "bin"
            target.mkdir()
            (target / "winPEASx64.exe").write_text("x", encoding="utf-8")

            matched, corrected = cli.fuzzy_translate(root, "/BIN/winpeasx64.exe")

            self.assertEqual(matched, target / "winPEASx64.exe")
            self.assertEqual(corrected, "/bin/winPEASx64.exe")

    def test_safe_join_rejects_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            joined = cli.safe_join(root, ["..", "etc", "passwd"])
            self.assertEqual(joined, root)


class MainTests(unittest.TestCase):
    def test_main_status_uses_state_file_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            serve_dir = Path(tmpdir) / "linux"
            serve_dir.mkdir()
            state_path = Path(tmpdir) / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "mode": "linux",
                        "lhost": "10.10.14.5",
                        "http_port": 8000,
                        "shell_port": 443,
                        "enable_smb": False,
                        "http_backend": "fuzzy",
                        "payload_root": tmpdir,
                        "serve_dir": str(serve_dir),
                        "base_url": "http://10.10.14.5:8000",
                        "smb_share_name": "PAYLOADS",
                        "smb_unc": "",
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"PAYLOAD_SERVER_STATE_FILE": str(state_path)}, clear=False):
                exit_code = cli.main(["status"])

            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
