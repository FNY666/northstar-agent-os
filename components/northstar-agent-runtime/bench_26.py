"""bench_26: Coverage harness.

Line coverage via settrace over a target module's exercised paths. Reports hit/total executable lines.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-26.v1"
SCHEMA_PIN = "northstar.bench-26.v1"

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
    target = _load("resource_defense")
    import sys as _s
    import ast as _a
    seen = set()

    def tracer(frame, event, arg):
        if event == "line" and frame.f_globals.get("__name__") ==                 "resource_defense":
            seen.add(frame.f_lineno)
        return tracer

    _s.settrace(tracer)
    try:
        target.check_resources("t", {"x": "f(f(x))"})
        target.check_resources("t", {"x": "ok"})
        target.check_nesting("a(b)", 5)
        target.check_repetition("a( a(", 10)
        target.check_size({"x": 1}, 100)
    finally:
        _s.settrace(None)
    tree = _a.parse(_Path(target.__file__).read_text(encoding="utf-8"))
    total = {n.lineno for n in _a.walk(tree) if isinstance(n, _a.stmt)}
    hit = seen & total
    return {"lines_total": len(total), "lines_hit": len(hit),
            "coverage": (len(hit) / len(total)) if total else 0.0}




def test_coverage_measured():
    s = run()
    assert s["lines_total"] > 0
    assert 0.0 < s["coverage"] <= 1.0


def test_some_lines_hit():
    assert run()["lines_hit"] > 10


def test_tracer_restored():
    import sys as _s
    run()
    assert _s.gettrace() is None


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-26.v1"
    assert SCHEMA_PIN == "northstar.bench-26.v1"



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
    print("bench-26 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
