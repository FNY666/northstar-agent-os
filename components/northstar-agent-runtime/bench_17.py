"""bench_17: Red-team suite.

Aggregates every attack probe family (injection, ASI02, Crescendo, BIPIA) into one runner: total arsenal size and per-family counts.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-17.v1"
SCHEMA_PIN = "northstar.bench-17.v1"

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
    inj = _load("injection_probe")
    a02 = _load("asi02_probe")
    cp = _load("crescendo_probe")
    bp = _load("bipia_probe")
    r1 = inj.run_all_probes(lambda t, o: False)
    r2 = a02.run_all(lambda t, a: False)
    scripts = len(cp.SCRIPTS)
    turns = sum(len(s.turns) for s in cp.SCRIPTS)
    positions = len(bp.build_position_probes("x", "y " * 10))
    families = {"injection": r1["total"], "asi02": r2["total"],
                "crescendo_scripts": scripts, "crescendo_turns": turns,
                "bipia_positions": positions}
    return {"families": families, "total_probes": sum(families.values())}




def test_four_families():
    s = run()
    assert len(s["families"]) == 5


def test_arsenal_nontrivial():
    s = run()
    assert s["total_probes"] >= 15


def test_crescendo_has_turns():
    s = run()
    assert s["families"]["crescendo_turns"] >= s["families"]["crescendo_scripts"]


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-17.v1"
    assert SCHEMA_PIN == "northstar.bench-17.v1"



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
    print("bench-17 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
