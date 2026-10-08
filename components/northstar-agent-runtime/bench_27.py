"""bench_27: Compliance checker.

Scans every bench module for required harness metadata: main(), stdlib_only(), BENCH_VERSION and SCHEMA_PIN. Reports violations.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time
import re

BENCH_VERSION = "bench-27.v1"
SCHEMA_PIN = "northstar.bench-27.v1"

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
    import re as _re
    d = _Path(__file__).resolve().parent
    files = sorted(d.glob("bench_*.py"))
    bad = []
    for p in files:
        src = p.read_text(encoding="utf-8")
        for attr in ("main", "stdlib_only"):
            if not _re.search(r"^def %s\(" % attr, src, _re.M):
                bad.append("%s:missing:%s" % (p.name, attr))
        for pin in ("BENCH_VERSION", "SCHEMA_PIN"):
            if pin not in src:
                bad.append("%s:missing:%s" % (p.name, pin))
    return {"checked": len(files), "violations": bad,
            "compliant": not bad}




def test_all_compliant():
    s = run()
    assert s["compliant"] is True, s["violations"]


def test_all_benches_checked():
    s = run()
    assert s["checked"] == 30


def test_no_violations():
    assert run()["violations"] == []



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time", "re"}
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
    print("bench-27 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
