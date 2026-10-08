"""bench_25: Mutation-test harness.

Mutates the gate config (drops one keyword at a time) and checks the corpus kills the mutant: at least one case must flip from blocked to allowed. Unkilled mutants mean weak tests.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-25.v1"
SCHEMA_PIN = "northstar.bench-25.v1"

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



KEYWORDS = ["evil", "rm -rf", "sudo"]
CASES = [("exec", {"cmd": "evil run"}), ("sh", {"cmd": "sudo ls"}),
         ("rm", {"cmd": "rm -rf /tmp/x"})]


def _make_gate(kws):
    tw = _load("tripwire_guardrails")
    return tw.TripwireGuard(
        "m", lambda t, a: any(k in str(a).lower() for k in kws),
        on_violation=tw.TripwireOutcome.HALT)


def _blocked(gate):
    tw = _load("tripwire_guardrails")
    return sum(1 for t, a in CASES
               if gate.check(t, a).outcome == tw.TripwireOutcome.HALT)


def run():
    base_blocked = _blocked(_make_gate(KEYWORDS))
    killed = 0
    survived = []
    for kw in KEYWORDS:
        mut = _make_gate([k for k in KEYWORDS if k != kw])
        if _blocked(mut) < base_blocked:
            killed += 1
        else:
            survived.append(kw)
    return {"mutants": len(KEYWORDS), "killed": killed,
            "survived": survived,
            "score": killed / len(KEYWORDS) if KEYWORDS else 0.0}




def test_mutants_killed():
    s = run()
    assert s["score"] >= 0.5


def test_base_blocks_all():
    assert _blocked(_make_gate(KEYWORDS)) == len(CASES)


def test_mutant_count():
    assert run()["mutants"] == 3


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-25.v1"
    assert SCHEMA_PIN == "northstar.bench-25.v1"



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
    print("bench-25 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
