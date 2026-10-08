"""bench_16: Integration benchmark.

Full pipeline: spotlight -> provenance tag -> tripwire -> command registry -> snapshot. Benign flows pass end to end; malicious ones are stopped and recorded.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-16.v1"
SCHEMA_PIN = "northstar.bench-16.v1"

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
    sp = _load("spotlighting")
    pt = _load("provenance_tagging")
    tw = _load("tripwire_guardrails")
    cr = _load("command_registry")
    ts = _load("task_snapshot")
    HALT = tw.TripwireOutcome.HALT
    nonce = sp.generate_nonce()
    gate = tw.TripwireGuard(
        "bench16", lambda t, a: "evil" in str(a).lower(), on_violation=HALT)
    reg = cr.CommandRegistry()
    reg.register(cr.CommandSpec(name="read",
                                autonomy=cr.AutonomyLevel.AUTOMATIC))
    snap = ts.TaskSnapshot("s16", "pipeline", {})

    def pipeline(item):
        marked = sp.delimit(str(item["args"]), nonce)
        pt.tag_tool_output(marked, tool_id=item["tool"])
        if gate.check(item["tool"], item["args"]).outcome == HALT:
            snap.add_tool_call(item["tool"], item["args"], "blocked", "deny")
            return False
        ok, _ = reg.check(item["tool"])
        snap.add_tool_call(item["tool"], item["args"],
                           "ok" if ok else "denied",
                           "allow" if ok else "deny")
        return bool(ok)

    benign = {"tool": "read", "args": {"path": "/tmp/x"}}
    evil = {"tool": "read", "args": {"path": "evil"}}
    t0 = time.perf_counter()
    b = pipeline(benign)
    e = pipeline(evil)
    ms = (time.perf_counter() - t0) * 1000 / 2
    return {"benign_allowed": b, "evil_blocked": not e, "avg_ms": ms,
            "calls": len(snap.tool_calls)}




def test_pipeline_blocks_evil():
    s = run()
    assert s["evil_blocked"] is True


def test_pipeline_allows_benign():
    s = run()
    assert s["benign_allowed"] is True


def test_everything_recorded():
    s = run()
    assert s["calls"] == 2


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-16.v1"
    assert SCHEMA_PIN == "northstar.bench-16.v1"



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
    print("bench-16 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
