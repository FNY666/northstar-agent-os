"""bench_14: Observability benchmark.

Interleaved reasoning enforcement (every action needs reasoning) plus span-style operation tracing for latency visibility.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-14.v1"
SCHEMA_PIN = "northstar.bench-14.v1"

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
    it = _load("interleaved_thinking")
    log = []
    runner = it.InterleavedRunner(
        executor=lambda tool, args: "result", log_fn=log.append)
    out = runner.run("need to read the file", "read", {"path": "/x"})
    missing_rejected = False
    try:
        runner.run(None, "read", {})
    except Exception:
        missing_rejected = True
    spans = []
    for i in range(10):
        t0 = time.perf_counter()
        runner.run("reason %d" % i, "read", {"path": "/x"})
        spans.append({"name": "op%d" % i,
                      "dur_ms": (time.perf_counter() - t0) * 1000})
    avg = sum(s["dur_ms"] for s in spans) / len(spans)
    return {"result": out, "logged": len(log) >= 1,
            "missing_reasoning_rejected": missing_rejected,
            "spans": len(spans), "avg_span_ms": avg}




def test_reasoning_enforced():
    s = run()
    assert s["missing_reasoning_rejected"] is True


def test_actions_logged():
    s = run()
    assert s["logged"] is True and s["result"] == "result"


def test_spans_recorded():
    s = run()
    assert s["spans"] == 10 and s["avg_span_ms"] >= 0


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-14.v1"
    assert SCHEMA_PIN == "northstar.bench-14.v1"



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
    print("bench-14 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
