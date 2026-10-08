"""bench_19: Purple-team benchmark.

Red vs blue: every attack family against the composite blue defense. Produces the block-rate matrix.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-19.v1"
SCHEMA_PIN = "northstar.bench-19.v1"

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



def _blue(tool, args):
    tw = _load("tripwire_guardrails")
    rd = _load("resource_defense")
    g = tw.TripwireGuard(
        "purple",
        lambda t, a: any(b in str(a).lower() for b in
                         ("evil", "rm -rf", "sudo", "ignore previous",
                          "system:", ";")),
        on_violation=tw.TripwireOutcome.HALT)
    if g.check(tool, args).outcome == tw.TripwireOutcome.HALT:
        return True
    ok, _ = rd.check_resources(tool, args)
    return not ok


def run():
    a02 = _load("asi02_probe")
    inj = _load("injection_probe")
    r = a02.run_all(_blue)
    matrix = {"asi02": r["blocked"] / r["total"]}
    r = inj.run_all_probes(lambda tid, out: _blue(tid, {"output": out}))
    matrix["injection"] = r["blocked"] / r["total"]
    worst = min(matrix.values())
    return {"matrix": matrix, "worst_family": min(matrix, key=matrix.get),
            "worst_rate": worst}




def test_matrix_has_families():
    s = run()
    assert set(s["matrix"]) == {"asi02", "injection"}


def test_rates_in_range():
    s = run()
    for v in s["matrix"].values():
        assert 0.0 <= v <= 1.0


def test_worst_consistent():
    s = run()
    assert s["worst_rate"] == min(s["matrix"].values())


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-19.v1"
    assert SCHEMA_PIN == "northstar.bench-19.v1"



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
    print("bench-19 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
