"""bench_22: Stress-test harness.

Concurrent gate checks from multiple threads: no errors, no lost updates, sustained throughput.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time
import threading

BENCH_VERSION = "bench-22.v1"
SCHEMA_PIN = "northstar.bench-22.v1"

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
    gate = tw.TripwireGuard(
        "bench22", lambda t, a: "evil" in str(a).lower())
    import threading as _th
    errors = []
    ops = [0]

    def worker(k):
        try:
            for _ in range(100):
                gate.check("read", {"path": "/tmp/%d" % k})
                ops[0] += 1
        except Exception as exc:
            errors.append(str(exc))

    threads = [_th.Thread(target=worker, args=(k,)) for k in range(8)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.perf_counter() - t0
    return {"threads": 8, "ops": ops[0], "errors": len(errors),
            "throughput_ops": ops[0] / dt if dt > 0 else 0.0}




def test_no_errors():
    s = run()
    assert s["errors"] == 0


def test_all_ops_completed():
    s = run()
    assert s["ops"] == 800


def test_throughput_positive():
    assert run()["throughput_ops"] > 0



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time"}, "threading"
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
    print("bench-22 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
