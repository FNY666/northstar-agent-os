#!/usr/bin/env python3
"""Run an explicit command and compare observed runtime imports to static inventory.

This is an opt-in execution tool: the command after ``--`` is executed with the
current user's privileges and inherited environment. It is not a sandbox. The
trace records only runtime module names and paths inside the selected runtime
checkout; stdout and stderr from the command pass through unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCRIPT = REPOSITORY_ROOT / "scripts" / "classify-runtime-modules.py"
DEFAULT_RUNTIME = REPOSITORY_ROOT / "components" / "northstar-agent-runtime"


# This module is loaded as ``sitecustomize`` by Python processes launched by
# the target command (and Python descendants that inherit the environment).
# Each process writes its own file so parallel child processes do not race.
_SITE_CUSTOMIZE = r'''"""Northstar's temporary, opt-in runtime import recorder."""
import atexit
import json
import os
import sys
import tempfile

_root = os.path.realpath(os.environ["NORTHSTAR_TRACE_RUNTIME_ROOT"])
_trace_dir = os.environ["NORTHSTAR_TRACE_OUTPUT_DIR"]

def _inside_root(path):
    try:
        return os.path.commonpath((_root, path)) == _root
    except (OSError, ValueError):
        return False

def _write_trace():
    modules = {}
    for name, module in tuple(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if not isinstance(path, str):
            continue
        resolved = os.path.realpath(path)
        if not _inside_root(resolved):
            continue
        relative = os.path.relpath(resolved, _root).replace(os.sep, "/")
        modules[name] = relative
    payload = {"pid": os.getpid(), "modules": modules}
    descriptor, temporary = tempfile.mkstemp(prefix=".trace-", dir=_trace_dir)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, os.path.join(_trace_dir, "process-%d.json" % os.getpid()))
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

atexit.register(_write_trace)
'''


def _load_inventory_module():
    spec = importlib.util.spec_from_file_location("northstar_runtime_inventory", INVENTORY_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load inventory analyzer: {INVENTORY_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Stop the command tree on timeout; do not leave traced descendants running."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - Northstar's supported runtime target is Linux
            process.terminate()
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    # The group leader can exit on TERM while a child ignores it. Always make
    # a final best-effort group kill before returning, then reap the leader.
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:  # pragma: no cover
            process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def run_trace(runtime: Path, command: list[str], output: Path, timeout: float, roots: list[str]) -> int:
    inventory_module = _load_inventory_module()
    static = inventory_module.inventory(runtime, roots or inventory_module.DEFAULT_ROOTS)
    if static["missing_roots"] or static["parse_errors"]:
        print(
            "error: refusing to run the command because the static inventory has missing roots or parse errors",
            file=sys.stderr,
        )
        return 2
    modules: dict[str, Path] = inventory_module.discover(runtime)
    path_to_module = {
        path.relative_to(runtime).as_posix(): name
        for name, path in modules.items()
    }
    static_reachable_paths = {
        modules[name].relative_to(runtime).as_posix()
        for name in static["core_reachable"]
    }

    with tempfile.TemporaryDirectory(prefix="northstar-runtime-import-trace-") as temporary:
        temporary_root = Path(temporary)
        trace_dir = temporary_root / "processes"
        trace_dir.mkdir()
        (temporary_root / "sitecustomize.py").write_text(_SITE_CUSTOMIZE, encoding="utf-8")
        env = os.environ.copy()
        runtime_path = str(runtime)
        injected_python_path = os.pathsep.join((str(temporary_root), runtime_path))
        if env.get("PYTHONPATH"):
            injected_python_path += os.pathsep + env["PYTHONPATH"]
        env["PYTHONPATH"] = injected_python_path
        env["NORTHSTAR_TRACE_RUNTIME_ROOT"] = runtime_path
        env["NORTHSTAR_TRACE_OUTPUT_DIR"] = str(trace_dir)

        process = subprocess.Popen(command, env=env, start_new_session=(os.name == "posix"))
        timed_out = False
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process(process)
            return_code = 124

        process_records: list[dict[str, Any]] = []
        for path in sorted(trace_dir.glob("process-*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(record, dict) and isinstance(record.get("modules"), dict):
                    process_records.append(record)
            except (OSError, json.JSONDecodeError):
                # A killed interpreter may not finish its trace; never infer
                # imports from a partial JSON file.
                continue

    observed: dict[str, set[str]] = {}
    for record in process_records:
        for name, relative_path in record["modules"].items():
            if isinstance(name, str) and isinstance(relative_path, str):
                observed.setdefault(relative_path, set()).add(name)
    observed_paths = set(observed)
    observed_rows = [
        {"path": path, "inventory_module": path_to_module.get(path), "runtime_names": sorted(observed[path])}
        for path in sorted(observed_paths)
    ]
    payload: dict[str, Any] = {
        "schema": "northstar.runtime-import-trace.v1",
        "runtime_root": runtime.name,
        "command_sha256": _canonical_hash(command),
        "return_code": return_code,
        "timed_out": timed_out,
        "traced_processes": len(process_records),
        "capture_completed": bool(process_records) and not timed_out,
        "coverage_limits": [
            "Only Python processes that load sitecustomize are captured; -S/-I, embedded interpreters, and children that drop PYTHONPATH can be missed.",
            "A completed trace covers only this command and its observed child processes, not every product path.",
        ],
        "static_inventory_sha256": static["inventory_sha256"],
        "static_analysis_complete": not static["missing_roots"] and not static["parse_errors"],
        "static_missing_roots": static["missing_roots"],
        "static_parse_errors": static["parse_errors"],
        "summary": {
            "observed_runtime_files": len(observed_paths),
            "observed_not_statically_reachable": len(observed_paths - static_reachable_paths),
            "statically_reachable_not_observed": len(static_reachable_paths - observed_paths),
            "dynamic_import_sites": static["summary"]["dynamic_import_sites"],
        },
        "observed_modules": observed_rows,
        "observed_not_statically_reachable": sorted(observed_paths - static_reachable_paths),
        "statically_reachable_not_observed": sorted(static_reachable_paths - observed_paths),
        "note": (
            "Observed imports are evidence for this command only; absence in a trace is not evidence that a module is unused. "
            "A clean command status is not a security or product-readiness claim."
        ),
    }
    payload["trace_sha256"] = _canonical_hash(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_output = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, output)
    finally:
        try:
            os.unlink(temporary_output)
        except FileNotFoundError:
            pass

    summary = payload["summary"]
    print(
        f"capture_completed={str(payload['capture_completed']).lower()} "
        f"traced_processes={payload['traced_processes']} "
        f"observed_runtime_files={summary['observed_runtime_files']} "
        f"observed_not_statically_reachable={summary['observed_not_statically_reachable']} "
        f"statically_reachable_not_observed={summary['statically_reachable_not_observed']}"
    )
    print(f"trace_sha256={payload['trace_sha256']}")
    print(f"wrote={output}")
    if timed_out:
        return 124
    if return_code == 0 and not process_records:
        print("warning: no Python process loaded sitecustomize; no runtime imports were observed", file=sys.stderr)
        return 2
    if return_code == 0 and not payload["static_analysis_complete"]:
        print("warning: static inventory had missing roots or parse errors", file=sys.stderr)
        return 2
    return return_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--output", type=Path, required=True, metavar="PATH")
    parser.add_argument("--timeout", type=float, default=300.0, help="command timeout in seconds (default: 300)")
    parser.add_argument("--root", action="append", default=[], dest="roots", help="static inventory root; repeatable")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to execute after --")
    args = parser.parse_args()
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    runtime = args.runtime.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not runtime.is_dir():
        parser.error(f"runtime directory does not exist: {runtime}")
    if not command:
        parser.error("provide a command after -- (for example: -- python3 -m cli bench)")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 86_400:
        parser.error("--timeout must be finite and between 0 and 86400 seconds")
    try:
        output.relative_to(runtime)
    except ValueError:
        pass
    else:
        parser.error("--output must not be inside the runtime tree")
    return run_trace(runtime, command, output, args.timeout, args.roots)


if __name__ == "__main__":
    raise SystemExit(main())
