"""bench_01: Injection benchmark.

Runs every injection probe suite (injection_probe, asi02_probe) against a reference gate and reports per-suite block rates.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-01.v1"
SCHEMA_PIN = "northstar.bench-01.v1"

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



def _gate_inj(tool_id, output):
    t = str(output).lower()
    return any(b in t for b in
               ("ignore previous", "system:", "reveal instructions", "disregard"))


def _gate_asi02(tool_name, args):
    t = str(args).lower()
    return any(b in t for b in ("evil", "rm -rf", "sudo", "os.system"))


def run():
    inj = _load("injection_probe")
    a02 = _load("asi02_probe")
    r1 = inj.run_all_probes(_gate_inj)
    r2 = a02.run_all(_gate_asi02)
    return {"injection_probe": r1, "asi02_probe": r2,
            "total": r1["total"] + r2["total"],
            "blocked": r1["blocked"] + r2["blocked"]}




def test_suites_present():
    s = run()
    assert "injection_probe" in s and "asi02_probe" in s


def test_totals_positive():
    s = run()
    assert s["total"] > 0
    assert s["injection_probe"]["total"] > 0
    assert s["asi02_probe"]["total"] > 0


def test_block_counts_consistent():
    s = run()
    assert 0 <= s["blocked"] <= s["total"]


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-01.v1"
    assert SCHEMA_PIN == "northstar.bench-01.v1"



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
    print("bench-01 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
