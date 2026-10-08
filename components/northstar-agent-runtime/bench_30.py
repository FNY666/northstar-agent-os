"""bench_30: Report generator.

Aggregates run() from bench_01..bench_29 into a single markdown report. The one harness that summarizes all harnesses.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time
import datetime
import os

BENCH_VERSION = "bench-30.v1"
SCHEMA_PIN = "northstar.bench-30.v1"

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
    import datetime as _dt
    rows = []
    for n in range(1, 30):
        name = "bench_%02d" % n
        try:
            m = _load(name)
            s = m.run()
            rows.append((name, "ok", str(s)[:90]))
        except Exception as exc:
            rows.append((name, "error", str(exc)[:90]))
    lines = ["# Northstar benchmark report", "",
             "generated: %sZ" % _dt.datetime.utcnow().isoformat(), "",
             "| bench | status | summary |",
             "|---|---|---|"]
    for name, st, summ in rows:
        lines.append("| %s | %s | %s |" % (name, st, summ))
    report = "\n".join(lines)
    out = "/tmp/northstar-bench-report.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    return {"benches": len(rows),
            "ok": sum(1 for r in rows if r[1] == "ok"),
            "report": out, "lines": len(lines)}




def test_all_benches_aggregated():
    s = run()
    assert s["benches"] == 29


def test_report_written():
    s = run()
    import os as _os
    assert _os.path.exists(s["report"])


def test_majority_ok():
    s = run()
    assert s["ok"] >= 25



def stdlib_only():
    import ast as _ast
    tree = _ast.parse(
        _Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "importlib", "pathlib", "sys", "time"}, "datetime", "os"
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
    print("bench-30 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
