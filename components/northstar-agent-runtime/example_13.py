"""Example 13: Mask PII, then spotlight the masked output.
Modules demonstrated: pii_vault + spotlighting
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pv = _load("pii_vault")
spot = _load("spotlighting")

vault = pv.Vault()

def run():
    text = "Contact alice@example.com or call 555-0100."
    masked, tokens = vault.mask(text, "run-1")
    marked, nonce = spot.spotlight(masked, level="delimit")
    restored = vault.demask(masked, "run-1")
    vault.clear_run("run-1")
    after = vault.demask(masked, "run-1")
    return {"masked": masked, "tokens": tokens, "nonce_ok": nonce in marked,
            "restored": restored, "cleared": after}

def main():
    r = run()
    assert "alice@example.com" not in r["masked"]
    assert len(r["tokens"]) >= 1
    assert r["nonce_ok"] is True
    assert r["restored"] != r["masked"]
    assert r["cleared"] == r["masked"]
    print("example_13 OK: pii vault + spotlighting")

if __name__ == "__main__":
    main()
