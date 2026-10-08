"""bench_18: Blue-team suite.

Aggregates the defenses: tripwire, resource limits, PII masking. Reports block rate on a malicious corpus and false-positive rate on a benign corpus.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-18.v1"
SCHEMA_PIN = "northstar.bench-18.v1"

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
    rd = _load("resource_defense")
    pv = _load("pii_vault")
    HALT = tw.TripwireOutcome.HALT
    gate = tw.TripwireGuard(
        "bench18",
        lambda t, a: any(b in str(a).lower() for b in ("evil", "rm -rf")),
        on_violation=HALT)
    malicious = [("exec", {"cmd": "evil"}), ("rm", {"a": "rm -rf /"}),
                 ("expand", {"i": "f(" * 12}), ("sh", {"c": "evil x"})]
    benign = [("read", {"path": "/tmp/x"}), ("list", {"dir": "/tmp"}),
              ("write", {"path": "/tmp/o"})]
    blocked = 0
    for t, a in malicious:
        hit = gate.check(t, a).outcome == HALT
        ok, _ = rd.check_resources(t, a)
        blocked += 1 if (hit or not ok) else 0
    fps = sum(1 for t, a in benign
              if gate.check(t, a).outcome == HALT)
    v = pv.Vault()
    m, _ = v.mask("a@b.com", run_id="b18")
    return {"malicious": len(malicious), "blocked": blocked,
            "block_rate": blocked / len(malicious),
            "benign": len(benign), "false_positives": fps,
            "fp_rate": fps / len(benign),
            "pii_masked": m != "a@b.com"}




def test_blocks_malicious():
    s = run()
    assert s["block_rate"] == 1.0


def test_no_false_positives():
    s = run()
    assert s["fp_rate"] == 0.0


def test_pii_masked():
    assert run()["pii_masked"] is True


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-18.v1"
    assert SCHEMA_PIN == "northstar.bench-18.v1"



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
    print("bench-18 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
