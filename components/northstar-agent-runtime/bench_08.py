"""bench_08: Runtime-defense benchmark.

Tripwire guardrails, deterministic veto, and resource defense over an action corpus. Every malicious action must be stopped; benign actions must pass.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-08.v1"
SCHEMA_PIN = "northstar.bench-08.v1"

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
    dv = _load("deterministic_veto")
    rd = _load("resource_defense")
    HALT = tw.TripwireOutcome.HALT
    ALLOW = tw.TripwireOutcome.ALLOW
    tripwire = tw.TripwireGuard(
        "bench08",
        lambda tool, args: any(
            b in str(args).lower() for b in ("evil", "rm -rf", "sudo")),
        on_violation=HALT)
    veto = dv.DeterministicVeto()
    veto.add_rule(dv.VetoRule("no_destruct", dv.Consequence.IRREVERSIBLE_BROAD))
    cases = [
        ("read", {"path": "/tmp/x"}, False),
        ("list", {"dir": "/tmp"}, False),
        ("exec", {"cmd": "evil payload"}, True),
        ("rm", {"path": "/"}, True),
        ("expand", {"input": "f(" * 20}, True),
    ]
    blocked = 0
    fps = 0
    for tool, args, expect_bad in cases:
        hit = tripwire.check(tool, args).outcome == HALT
        ok, _ = rd.check_resources(tool, args)
        hit = hit or not ok
        if tool == "rm":
            vetoed, _ = veto.check(dv.Consequence.IRREVERSIBLE_BROAD)
            hit = hit or vetoed
        if expect_bad and hit:
            blocked += 1
        if not expect_bad and hit:
            fps += 1
    return {"total": len(cases), "malicious_blocked": blocked,
            "malicious": 3, "false_positives": fps}




def test_all_malicious_blocked():
    s = run()
    assert s["malicious_blocked"] == s["malicious"]


def test_no_false_positives():
    s = run()
    assert s["false_positives"] == 0


def test_benign_allowed():
    tw = _load("tripwire_guardrails")
    g = tw.TripwireGuard("t", lambda tool, args: False)
    assert g.check("read", {"p": "/x"}).outcome == tw.TripwireOutcome.ALLOW


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-08.v1"
    assert SCHEMA_PIN == "northstar.bench-08.v1"



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
    print("bench-08 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
