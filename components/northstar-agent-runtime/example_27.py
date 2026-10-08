"""Example 27: Masked PII keeps its provenance tag.
Modules demonstrated: pii_vault + provenance_tagging
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
prov = _load("provenance_tagging")

vault = pv.Vault()

def run():
    raw = prov.tag_tool_output("email bob@example.com here", "crm_tool")
    masked_text, tokens = vault.mask(raw.value, "run-7")
    masked_tag = prov.tag_tool_output(masked_text, "pii_vault")
    combined = prov.combine(raw, masked_tag)
    return {"masked": masked_text, "tokens": tokens, "deps": combined.deps}

def main():
    r = run()
    assert "bob@example.com" not in r["masked"]
    assert len(r["tokens"]) >= 1
    assert "crm_tool" in r["deps"] and "pii_vault" in r["deps"]
    print("example_27 OK: pii vault + provenance")

if __name__ == "__main__":
    main()
