"""bench_24: Property-test harness.

Invariants over generated cases: determinism (same input, same decision), fail-closed (gate exceptions become blocks), monotonicity (stricter limits block at least as much).

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-24.v1"
SCHEMA_PIN = "northstar.bench-24.v1"

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
    tw = _load("tripwire_guardrails")
    rd = _load("resource_defense")
    g = tw.TripwireGuard("p", lambda t, a: "evil" in str(a).lower())
    first = g.check("read", {"p": "/x"}).outcome
    det = all(g.check("read", {"p": "/x"}).outcome == first
              for _ in range(20))

    def boom(t, a):
        raise RuntimeError("gate exploded")

    g2 = tw.TripwireGuard("p2", boom)
    fc = False
    try:
        g2.check("read", {})
    except Exception:
        fc = True
    strict = rd.ResourceLimits(max_nesting_depth=2)
    loose = rd.ResourceLimits(max_nesting_depth=50)
    cases = [{"x": "f(" * d} for d in range(1, 8)]
    s = sum(1 for c in cases if not rd.check_resources("t", c, strict)[0])
    l = sum(1 for c in cases if not rd.check_resources("t", c, loose)[0])
    return {"deterministic": det, "fail_closed": fc, "monotone": s >= l,
            "strict_blocks": s, "loose_blocks": l}




def test_deterministic():
    assert run()["deterministic"] is True


def test_fail_closed():
    assert run()["fail_closed"] is True


def test_monotone():
    s = run()
    assert s["monotone"] is True
    assert s["strict_blocks"] >= s["loose_blocks"]


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-24.v1"
    assert SCHEMA_PIN == "northstar.bench-24.v1"



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
    print("bench-24 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
