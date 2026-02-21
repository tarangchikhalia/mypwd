import io
import stat
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

import mypwd


class MyPwdTests(unittest.TestCase):
    def test_add_password_persists_username_and_password(self):
        mock_cipher = MagicMock(name="cipher")
        existing_passwords = {"email": "olduser:oldpass"}

        with patch("mypwd.get_master_key", return_value=mock_cipher) as mock_get_key, \
            patch("mypwd.load_passwords", return_value=existing_passwords.copy()) as mock_load, \
            patch("mypwd.save_passwords") as mock_save, \
            redirect_stdout(io.StringIO()):
            mypwd.add_password("github", "octocat", "token123")

        self.assertTrue(mock_get_key.called)
        self.assertTrue(mock_load.called)
        mock_save.assert_called_once()
        saved_cipher, saved_payload = mock_save.call_args.args
        self.assertIs(saved_cipher, mock_cipher)
        self.assertEqual(saved_payload["email"], "olduser:oldpass")
        self.assertEqual(saved_payload["github"], "octocat:token123")

    def test_add_password_overwrites_existing_entry(self):
        mock_cipher = MagicMock(name="cipher")

        with patch("mypwd.get_master_key", return_value=mock_cipher), \
            patch("mypwd.load_passwords", return_value={"github": "old:entry"}), \
            patch("mypwd.save_passwords") as mock_save, \
            redirect_stdout(io.StringIO()):
            mypwd.add_password("github", "octocat", "token123")

        saved_payload = mock_save.call_args.args[1]
        self.assertEqual(saved_payload["github"], "octocat:token123")

    def test_get_password_with_output_prints_username_and_password(self):
        with patch("mypwd.get_master_key"), \
            patch("mypwd.load_passwords", return_value={"github": "octocat:swordfish"}):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                mypwd.get_password("github", output=True)

        output = buffer.getvalue()
        self.assertIn("Username: octocat", output)
        self.assertIn("Password: swordfish", output)

    def test_get_password_without_output_uses_clipboard(self):
        fake_pyperclip = types.ModuleType("pyperclip")
        fake_pyperclip.copy = MagicMock()

        with patch("mypwd.get_master_key"), \
            patch("mypwd.load_passwords", return_value={"github": "octocat:swordfish"}), \
            patch.dict(sys.modules, {"pyperclip": fake_pyperclip}):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                mypwd.get_password("github")

        fake_pyperclip.copy.assert_called_once_with("swordfish")
        output = buffer.getvalue()
        self.assertIn("Username for 'github' is 'octocat'", output)
        self.assertIn("Password for 'github' copied to clipboard.", output)

    def test_get_password_missing_tag_exits_with_error(self):
        with patch("mypwd.get_master_key"), \
            patch("mypwd.load_passwords", return_value={"email": "user:pass"}):
            buffer = io.StringIO()
            with redirect_stderr(buffer), self.assertRaises(SystemExit):
                mypwd.get_password("github", output=True)

        error_output = buffer.getvalue()
        self.assertIn("Error: No password found for tag 'github'", error_output)

    def test_main_add_uses_prompt_password(self):
        argv = [
            "mypwd.py",
            "--add",
            "github",
            "--username",
            "octocat",
        ]
        with patch.object(sys, "argv", argv), \
            patch("mypwd.getpass.getpass", return_value="prompt-secret"), \
            patch("mypwd.add_password") as mock_add:
            mypwd.main()

        mock_add.assert_called_once_with("github", "octocat", "prompt-secret")

    def test_main_add_uses_stdin_password(self):
        argv = [
            "mypwd.py",
            "--add",
            "github",
            "--username",
            "octocat",
            "--password-stdin",
        ]
        with patch.object(sys, "argv", argv), \
            patch("sys.stdin", io.StringIO("stdin-secret\n")), \
            patch("mypwd.add_password") as mock_add:
            mypwd.main()

        mock_add.assert_called_once_with("github", "octocat", "stdin-secret")

    def test_main_add_requires_username(self):
        argv = ["mypwd.py", "--add", "github"]
        buffer = io.StringIO()
        with patch.object(sys, "argv", argv), redirect_stderr(buffer), self.assertRaises(
            SystemExit
        ):
            mypwd.main()

        self.assertIn("--username is required when using --add", buffer.getvalue())

    def test_ensure_storage_dir_secure_uses_0700(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secure_dir = Path(tmpdir) / "mypwd"
            with patch.object(mypwd, "STORAGE_DIR", secure_dir):
                mypwd.ensure_storage_dir_secure()
                mode = stat.S_IMODE(secure_dir.stat().st_mode)
                self.assertEqual(mode, mypwd.STORAGE_DIR_MODE)

    def test_save_passwords_uses_0600_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secure_dir = Path(tmpdir) / "mypwd"
            storage_file = secure_dir / "passwords.enc"
            cipher = MagicMock()
            cipher.encrypt.return_value = b"encrypted"
            with patch.object(mypwd, "STORAGE_DIR", secure_dir), patch.object(
                mypwd, "STORAGE_FILE", storage_file
            ):
                mypwd.save_passwords(cipher, {"github": "octocat:swordfish"})

            dir_mode = stat.S_IMODE(secure_dir.stat().st_mode)
            file_mode = stat.S_IMODE(storage_file.stat().st_mode)
            self.assertEqual(dir_mode, mypwd.STORAGE_DIR_MODE)
            self.assertEqual(file_mode, mypwd.STORAGE_FILE_MODE)


if __name__ == "__main__":
    unittest.main()
