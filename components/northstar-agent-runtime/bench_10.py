"""bench_10: Monitoring benchmark.

Lifecycle hook throughput plus stateful veto escalation: repeated denials must raise risk and trigger rate limiting.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-10.v1"
SCHEMA_PIN = "northstar.bench-10.v1"

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
    lh = _load("lifecycle_hooks")
    sv = _load("stateful_veto")
    reg = lh.HookRegistry()
    seen = []
    reg.register(lh.HookPoint.PRE_TOOL, lambda ctx: seen.append(ctx) or True)
    n = 200
    t0 = time.perf_counter()
    for i in range(n):
        ok, _ = reg.fire(lh.HookPoint.PRE_TOOL, {"tool": "read", "i": i})
        assert ok
    fire_ms = (time.perf_counter() - t0) * 1000 / n
    veto = sv.StatefulVeto()
    for _ in range(4):
        veto.record_deny("sess1", "exec")
    limited, _ = veto.should_rate_limit("sess1", "exec")
    return {"fires": n, "hooks_seen": len(seen), "avg_fire_ms": fire_ms,
            "rate_limited": limited, "risk": veto.risk_score("sess1")}




def test_hooks_all_fired():
    s = run()
    assert s["hooks_seen"] == s["fires"]


def test_repeated_denials_rate_limited():
    s = run()
    assert s["rate_limited"] is True


def test_risk_increases():
    s = run()
    assert s["risk"] > 0


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-10.v1"
    assert SCHEMA_PIN == "northstar.bench-10.v1"



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
    print("bench-10 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
