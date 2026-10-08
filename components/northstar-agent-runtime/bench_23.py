"""bench_23: Fuzzing harness.

Seeded random inputs into parsers and validators. Crash-free is the bar: any exception on hostile input is fail-closed, never a crash.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time
import random

BENCH_VERSION = "bench-23.v1"
SCHEMA_PIN = "northstar.bench-23.v1"

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
    sp = _load("spotlighting")
    rd = _load("resource_defense")
    import random as _random
    rng = _random.Random(42)
    alphabet = "abcXYZ019 \n\t()[]{};:'\"\\<>&|"
    crashes = 0
    n = 300
    for _ in range(n):
        s = "".join(rng.choice(alphabet)
                     for _ in range(rng.randint(0, 200)))
        try:
            nonce = sp.generate_nonce()
            sp.delimit(s, nonce)
            rd.check_resources("fuzz", {"x": s})
        except Exception:
            crashes += 1
    return {"inputs": n, "crashes": crashes, "crash_free": crashes == 0}




def test_crash_free():
    s = run()
    assert s["crash_free"] is True


def test_inputs_generated():
    assert run()["inputs"] == 300


def test_deterministic_seed():
    import random as _random
    a = _random.Random(42).randint(0, 10**6)
    b = _random.Random(42).randint(0, 10**6)
    assert a == b



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time", "random"}
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
    print("bench-23 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
