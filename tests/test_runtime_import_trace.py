"""Tests for the opt-in runtime import tracer."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trace-runtime-imports.py"
SPEC = importlib.util.spec_from_file_location("runtime_import_trace", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeImportTraceTests(unittest.TestCase):
    def make_runtime(self, parent: Path) -> Path:
        runtime = parent / "runtime"
        runtime.mkdir()
        (runtime / "cli.py").write_text("import helper\n", encoding="utf-8")
        (runtime / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        (runtime / "orphan.py").write_text("VALUE = 2\n", encoding="utf-8")
        return runtime

    def run_quietly(self, *args: object) -> int:
        with contextlib.redirect_stdout(StringIO()), contextlib.redirect_stderr(StringIO()):
            return MODULE.run_trace(*args)  # type: ignore[arg-type]

    def test_direct_and_child_process_imports_are_compared_to_static_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = self.make_runtime(parent)
            output = parent / "trace.json"
            child = "import orphan"
            code = (
                "import cli, subprocess, sys; "
                f"subprocess.run([sys.executable, '-c', {child!r}], check=True)"
            )
            result = self.run_quietly(runtime, [sys.executable, "-c", code], output, 10.0, ["cli"])
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertTrue(report["capture_completed"])
        self.assertEqual(report["traced_processes"], 2)
        self.assertEqual(report["summary"]["observed_runtime_files"], 3)
        self.assertEqual(report["summary"]["observed_not_statically_reachable"], 1)
        self.assertEqual(report["observed_not_statically_reachable"], ["orphan.py"])
        self.assertEqual(report["statically_reachable_not_observed"], [])
        self.assertEqual(report["schema"], "northstar.runtime-import-trace.v1")

    def test_nonzero_command_status_is_preserved_and_trace_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = self.make_runtime(parent)
            output = parent / "trace.json"
            result = self.run_quietly(
                runtime,
                [sys.executable, "-c", "import cli, sys; sys.exit(7)"],
                output,
                10.0,
                ["cli"],
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result, 7)
        self.assertEqual(report["return_code"], 7)
        self.assertTrue(report["capture_completed"])

    def test_python_isolated_from_sitecustomize_is_reported_as_untraced(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = self.make_runtime(parent)
            output = parent / "trace.json"
            result = self.run_quietly(
                runtime,
                [sys.executable, "-S", "-c", "pass"],
                output,
                10.0,
                ["cli"],
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result, 2)
        self.assertFalse(report["capture_completed"])
        self.assertEqual(report["traced_processes"], 0)

    def test_nonfinite_timeout_is_rejected_before_command_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trace.json"
            argv = [
                str(SCRIPT),
                "--output",
                str(output),
                "--timeout",
                "nan",
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(99)",
            ]
            with patch.object(sys, "argv", argv), contextlib.redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    MODULE.main()

        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(output.exists(), "invalid timeout must not launch or write a report")

    def test_missing_static_root_refuses_to_start_command(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = self.make_runtime(parent)
            output = parent / "trace.json"
            marker = parent / "must-not-exist"
            code = f"from pathlib import Path; Path({str(marker)!r}).touch()"
            with contextlib.redirect_stderr(StringIO()):
                result = MODULE.run_trace(
                    runtime,
                    [sys.executable, "-c", code],
                    output,
                    10.0,
                    ["missing_root"],
                )

        self.assertEqual(result, 2)
        self.assertFalse(marker.exists(), "invalid inventory roots must fail before execution")
        self.assertFalse(output.exists())

    def test_timeout_is_reported_without_leaving_the_command_running(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            runtime = self.make_runtime(parent)
            output = parent / "trace.json"
            result = self.run_quietly(
                runtime,
                [sys.executable, "-c", "import cli, time; time.sleep(30)"],
                output,
                0.1,
                ["cli"],
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result, 124)
        self.assertTrue(report["timed_out"])
        self.assertFalse(report["capture_completed"])


if __name__ == "__main__":
    unittest.main()
