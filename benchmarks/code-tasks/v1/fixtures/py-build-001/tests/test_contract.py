import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from backend import build_wheel


class WheelTests(unittest.TestCase):
    def test_installed_package_reads_its_template(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / build_wheel(root)
            installed = root / "site"
            installed.mkdir()
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(installed)
            program = "import sys; sys.path.insert(0, sys.argv[1]); from demo_templates import render; print(render('Ada'))"
            result = subprocess.run([sys.executable, "-I", "-c", program, str(installed)], cwd=root, text=True, capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "Hello, Ada!")


if __name__ == "__main__":
    unittest.main()
