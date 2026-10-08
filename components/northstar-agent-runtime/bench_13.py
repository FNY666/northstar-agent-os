"""bench_13: State-management benchmark.

Task snapshots (replayable forensic artifacts) plus provenance policy: untrusted tool output must not flow into privileged sinks.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-13.v1"
SCHEMA_PIN = "northstar.bench-13.v1"

import importlib.util
import sys as _sys
from pathlib import Path as _Path

_RUNTIME = _Path(__file__).resolve().parent
_modcache = {}


def _load(name):
    if name not in _modcache:
        spec = importlib.util.spec_from_file_location(
            name, _RUNTIME / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        _sys.modules[name] = module
        spec.loader.exec_module(module)
        _modcache[name] = module
    return _modcache[name]


def run_suite(cases, fn):
    results = []
    for case in cases:
        t0 = time.perf_counter()
        try:
            ok = bool(fn(case))
            err = None
        except Exception as exc:
            ok, err = False, str(exc)
        results.append({"case": repr(case)[:60], "ok": ok, "error": err,
                        "ms": (time.perf_counter() - t0) * 1000})
    return results


def summarize(results):
    n = len(results)
    ok = sum(1 for r in results if r["ok"])
    return {"total": n, "passed": ok, "failed": n - ok,
            "pass_rate": (ok / n) if n else 0.0,
            "avg_ms": (sum(r["ms"] for r in results) / n) if n else 0.0}



def run():
    ts = _load("task_snapshot")
    pt = _load("provenance_tagging")
    snap = ts.TaskSnapshot("s1", "do task", {"model": "x"})
    for i in range(3):
        snap.add_tool_call("read", {"p": "/f%d" % i}, "ok", "allow")
    h = snap.snapshot_hash()
    tagged = pt.tag_tool_output("secret data", tool_id="db_reader")
    denied = pt.check_policy(
        "send_email", {"body": tagged},
        {"send_email": {"allowed_sources": {"user", "internal"}}})
    user_tagged = pt.tag_user("hello")
    allowed = pt.check_policy(
        "send_email", {"body": user_tagged},
        {"send_email": {"allowed_sources": {"user", "internal"}}})
    return {"calls": len(snap.tool_calls),
            "hash_ok": h.startswith("sha256:"),
            "untrusted_denied": not denied,
            "user_allowed": bool(allowed)}




def test_snapshot_roundtrip():
    s = run()
    assert s["calls"] == 3 and s["hash_ok"] is True


def test_provenance_policy():
    s = run()
    assert s["untrusted_denied"] is True
    assert s["user_allowed"] is True


def test_hash_deterministic():
    ts = _load("task_snapshot")
    a = ts.TaskSnapshot("s", "p", {})
    b = ts.TaskSnapshot("s", "p", {})
    assert a.snapshot_hash() == b.snapshot_hash()


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-13.v1"
    assert SCHEMA_PIN == "northstar.bench-13.v1"



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time"}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, _ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def _run_tests():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed, failed = 0, []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as exc:
            failed.append((t.__name__, str(exc)))
    return passed, failed


def main():
    passed, failed = _run_tests()
    assert stdlib_only(), "stdlib-only check failed"
    print("bench-13 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
