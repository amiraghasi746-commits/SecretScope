import tempfile
import unittest
from pathlib import Path

from secretscope.scanner import Scanner


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_scan_file_detects_signature_match(self):
        path = self._write("config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
        scanner = Scanner()
        findings = scanner.scan_path(path)
        self.assertTrue(any(f.rule == "AWS Access Key ID" for f in findings))

    def test_scan_file_with_no_secrets_returns_empty(self):
        path = self._write("clean.py", "def hello():\n    return 'hello world'\n")
        scanner = Scanner()
        findings = scanner.scan_path(path)
        self.assertEqual(findings, [])

    def test_scan_directory_recurses_into_subfolders(self):
        (self.root / "sub").mkdir()
        self._write("sub/secret.py", 'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n')
        self._write("plain.py", "x = 1\n")

        scanner = Scanner()
        findings = scanner.scan_path(self.root)
        matched_files = {f.file_path for f in findings}
        self.assertTrue(any("secret.py" in f for f in matched_files))

    def test_ignored_directories_are_skipped(self):
        (self.root / "node_modules").mkdir()
        self._write("node_modules/bundle.js", 'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"\n')

        scanner = Scanner()
        findings = scanner.scan_path(self.root)
        self.assertEqual(findings, [])

    def test_entropy_check_can_be_disabled(self):
        path = self._write("data.py", 'random_val = "aK9x2LpQz7mN4vWbR8tYc1sJ9Zq3"\n')
        scanner = Scanner(enable_entropy_check=False)
        findings = scanner.scan_path(path)
        self.assertFalse(any(f.rule == "High-Entropy String" for f in findings))

    def test_scan_nonexistent_path_raises(self):
        scanner = Scanner()
        with self.assertRaises(FileNotFoundError):
            scanner.scan_path(self.root / "does_not_exist.py")


if __name__ == "__main__":
    unittest.main()
