"""bench_11: Code-execution benchmark.

Command registry: autonomy tiers over a command corpus. Automatic commands pass, approval-gated ones need human approval, unknown ones are denied.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-11.v1"
SCHEMA_PIN = "northstar.bench-11.v1"

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
    cr = _load("command_registry")
    reg = cr.CommandRegistry()
    A = cr.AutonomyLevel
    reg.register(cr.CommandSpec(name="read_file", autonomy=A.AUTOMATIC,
                                description="read a file"))
    reg.register(cr.CommandSpec(name="exec_shell", autonomy=A.APPROVAL_REQUIRED,
                                description="run shell"))
    reg.register(cr.CommandSpec(name="drop_db", autonomy=A.HUMAN_ONLY,
                                description="danger"))
    ok_read, _ = reg.check("read_file")
    ok_exec, _ = reg.check("exec_shell")
    ok_exec2, _ = reg.check("exec_shell", human_approved=True)
    ok_unknown, _ = reg.check("nope")
    return {"auto_allowed": bool(ok_read),
            "approval_denied_without_human": not ok_exec,
            "approval_granted_with_human": bool(ok_exec2),
            "unknown_denied": not ok_unknown}




def test_auto_command_allowed():
    assert run()["auto_allowed"] is True


def test_approval_gating():
    s = run()
    assert s["approval_denied_without_human"] is True
    assert s["approval_granted_with_human"] is True


def test_unknown_denied():
    assert run()["unknown_denied"] is True


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-11.v1"
    assert SCHEMA_PIN == "northstar.bench-11.v1"



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
    print("bench-11 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
