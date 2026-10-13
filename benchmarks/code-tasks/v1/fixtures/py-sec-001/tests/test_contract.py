import unittest
from unittest.mock import patch
import tempfile
import stat
from pathlib import Path
from zipfile import ZipFile, ZipInfo
from archive import extract


class ContractTests(unittest.TestCase):
    def test_safe_nested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ZipFile(root / "input.zip", "w") as source:
                source.writestr("nested/a.txt", "hello")
            self.assertEqual(extract(root / "input.zip", root / "out"), ["nested/a.txt"])
            self.assertEqual((root / "out/nested/a.txt").read_text(), "hello")

    def test_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ZipFile(root / "input.zip", "w") as source:
                source.writestr("../escape.txt", "no")
            with self.assertRaises(ValueError):
                extract(root / "input.zip", root / "out")


if __name__ == "__main__":
    unittest.main()
