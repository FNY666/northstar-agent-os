import unittest
from unittest.mock import patch
import tempfile
import stat
from pathlib import Path
from zipfile import ZipFile, ZipInfo
from archive import extract


class ContractTests(unittest.TestCase):
    def test_absolute_and_windows(self):
        for name in ("/absolute.txt", "C:/escape.txt", "..\\escape.txt"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with ZipFile(root / "input.zip", "w") as source:
                    source.writestr(name, "no")
                with self.assertRaises(ValueError):
                    extract(root / "input.zip", root / "out")

    def test_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with ZipFile(root / "input.zip", "w") as source:
                source.writestr(link, "../outside")
            with self.assertRaises(ValueError):
                extract(root / "input.zip", root / "out")

    def test_existing_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "out").mkdir()
            (root / "outside").mkdir()
            (root / "out/link").symlink_to(root / "outside", target_is_directory=True)
            with ZipFile(root / "input.zip", "w") as source:
                source.writestr("link/a.txt", "no")
            with self.assertRaises(ValueError):
                extract(root / "input.zip", root / "out")
            self.assertFalse((root / "outside/a.txt").exists())


if __name__ == "__main__":
    unittest.main()
