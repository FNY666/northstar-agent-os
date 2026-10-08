"""Example 15: Per-hop schema validation with provenance tags.
Modules demonstrated: hop_validation + provenance_tagging
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


hv = _load("hop_validation")
prov = _load("provenance_tagging")

schema = hv.HopSchema("hop1", allowed_fields={"text", "tool"}, required_fields={"text"}, max_size=1000)

def run():
    tagged = prov.tag_tool_output("agent said hi", "agent-1")
    payload = {"text": tagged.value, "tool": "agent-1"}
    valid = hv.validate_hop(payload, schema)
    # Provenance follows the hop.
    combined = prov.combine(tagged, prov.tag_user("user note"))
    return {"valid": valid, "provenance": combined.provenance,
            "deps": combined.deps, "readers": combined.readers}

def main():
    r = run()
    assert r["valid"]["text"] == "agent said hi"
    assert "agent-1" in r["deps"]
    # Hop with unknown field is isolated.
    try:
        hv.validate_hop({"text": "x", "evil": 1}, schema)
        isolated = False
    except hv.HopValidationError:
        isolated = True
    assert isolated is True
    print("example_15 OK: hop validation + provenance")

if __name__ == "__main__":
    main()
