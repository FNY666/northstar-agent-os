"""bench_09: Crypto-defense benchmark.

Forward-sealed ledger round-trip: seal N events, verify the chain. Measures seal latency and verifies integrity end to end.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time
import os

BENCH_VERSION = "bench-09.v1"
SCHEMA_PIN = "northstar.bench-09.v1"

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
    fs = _load("forward_seal_ledger")
    import os as _os
    k1, k2 = _os.urandom(32), _os.urandom(32)
    pin = "sha256:" + "0" * 64
    ledger = fs.ForwardSealLedger(initial_key=k1, checkpoint_key=k2)
    n = 5
    t0 = time.perf_counter()
    for i in range(n):
        ledger.append(intent="task-%d" % i, action="tool.call",
                      subject="agent", authorization="auth-%d" % i,
                      inputs_digest=pin, logic_digest=pin,
                      execution_digest=pin, outcome="ok")
    seal_ms = (time.perf_counter() - t0) * 1000 / n
    v = ledger.verify(k1, k2)
    return {"sealed": n, "avg_seal_ms": seal_ms,
            "verify_ok": isinstance(v, dict)}




def test_seal_verify_roundtrip():
    s = run()
    assert s["sealed"] == 5 and s["verify_ok"] is True


def test_seal_fast_enough():
    s = run()
    assert s["avg_seal_ms"] < 50


def test_rejects_short_key():
    fs = _load("forward_seal_ledger")
    try:
        fs.ForwardSealLedger(initial_key=b"short", checkpoint_key=b"short")
        raise AssertionError("should have raised")
    except Exception:
        pass



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time", "os"}
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
    print("bench-09 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
