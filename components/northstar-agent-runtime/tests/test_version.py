"""The version string has exactly one home, so nothing can drift."""
from __future__ import annotations

import io
import contextlib
import unittest

import _version
import cli


class VersionConsistencyTests(unittest.TestCase):
    def test_cli_imports_the_single_source_of_truth(self):
        # cli's module-level import means the printed version is the module's.
        import cli as cli_module

        self.assertIs(cli_module.__version__, _version.__version__)
        self.assertTrue(_version.__version__)

    def test_help_mentions_the_doctor_subcommand(self):
        parser = cli.build_parser()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--help"])
        self.assertIn("doctor", out.getvalue())
        self.assertIn("--version", out.getvalue())


if __name__ == "__main__":
    unittest.main()
