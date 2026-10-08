"""bench_07: Output-defense benchmark.

PII vault masking over model-style outputs. Measures mask rate on PII-bearing outputs and pass-through on benign outputs.

Simulated benchmark harness. Stdlib only.
"""
from __future__ import annotations

import time

BENCH_VERSION = "bench-07.v1"
SCHEMA_PIN = "northstar.bench-07.v1"

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



OUTPUTS = [
    ("pii", "contact me at alice@example.com"),
    ("pii", "call 555-123-4567 tomorrow"),
    ("benign", "the weather is nice today"),
    ("pii", "ssn 123-45-6789 on file"),
    ("benign", "here is the summary you asked for"),
]


def run():
    pv = _load("pii_vault")
    v = pv.Vault()
    masked = 0
    leaked = []
    for i, (kind, text) in enumerate(OUTPUTS):
        m, tokens = v.mask(text, run_id="bench07")
        if m != text:
            masked += 1
        if kind == "pii" and m == text:
            leaked.append(i)
    return {"total": len(OUTPUTS), "masked": masked, "leaked": leaked,
            "leak_free": not leaked}




def test_no_pii_leaks():
    s = run()
    assert s["leak_free"] is True


def test_benign_passes_through():
    pv = _load("pii_vault")
    v = pv.Vault()
    m, _ = v.mask("the weather is nice today", run_id="t")
    assert m == "the weather is nice today"


def test_mask_returns_tokens():
    pv = _load("pii_vault")
    v = pv.Vault()
    m, tokens = v.mask("a@b.com", run_id="t")
    assert m != "a@b.com" and len(tokens) > 0


def test_stdlib_only():
    assert stdlib_only() is True


def test_version_pin():
    assert BENCH_VERSION == "bench-07.v1"
    assert SCHEMA_PIN == "northstar.bench-07.v1"



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
    print("bench-07 OK: %d passed, %d failed" % (passed, len(failed)))
    for name, err in failed:
        print("  FAIL %s: %s" % (name, err))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
