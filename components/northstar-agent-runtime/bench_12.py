"""bench_12: Tool-system benchmark.

Tool definition pinning (rug-pull detection) and hop schema validation. Drifted definitions and malformed hops must be rejected.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-12.v1"
SCHEMA_PIN = "northstar.bench-12.v1"

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
    tp = _load("tool_pinning")
    hv = _load("hop_validation")
    reg = tp.ToolRegistry()
    definition = {"name": "read", "params": ["path"]}
    reg.pin("read", definition, pinned_by="bench12")
    same = reg.verify("read", definition)
    drifted = reg.verify("read", {"name": "read", "params": ["path", "extra"]})
    schema = hv.HopSchema(hop_id="h1",
                          allowed_fields=frozenset({"a", "b"}),
                          required_fields=frozenset({"a"}))
    good = hv.validate_hop({"a": 1, "b": 2}, schema)
    bad_rejected = False
    try:
        hv.validate_hop({"b": 2}, schema)
    except Exception:
        bad_rejected = True
    extra_stripped = hv.validate_hop({"a": 1, "zzz": 9}, schema)
    return {"pin_same_ok": bool(same),
            "pin_drift_detected": not drifted,
            "hop_good": "a" in good,
            "hop_bad_rejected": bad_rejected,
            "hop_extra_stripped": "zzz" not in extra_stripped}




def test_rug_pull_detected():
    s = run()
    assert s["pin_same_ok"] is True
    assert s["pin_drift_detected"] is True


def test_hop_validation():
    s = run()
    assert s["hop_good"] is True
    assert s["hop_bad_rejected"] is True
    assert s["hop_extra_stripped"] is True


def test_hash_stable():
    tp = _load("tool_pinning")
    d = {"a": 1}
    assert tp.hash_definition(d) == tp.hash_definition(d)


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-12.v1"
    assert SCHEMA_PIN == "northstar.bench-12.v1"



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
    print("bench-12 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
