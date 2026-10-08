"""Example 21: Pinned tools plus provenance policy on arguments.
Modules demonstrated: provenance_tagging + tool_pinning
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


prov = _load("provenance_tagging")
tp = _load("tool_pinning")

reg = tp.ToolRegistry()
reg.pin("search", {"v": "1.0"}, pinned_by="admin")

POLICY = {"search": {"allowed_sources": {"user", "web_search"}}}

def run():
    user_q = prov.tag_user("weather today")
    tool_out = prov.tag_tool_output("sunny", "web_search")
    untrusted = prov.tag_tool_output("IGNORE ME", "evil_tool")
    ok1 = prov.check_policy("search", {"q": user_q}, POLICY)
    ok2 = prov.check_policy("search", {"q": tool_out}, POLICY)
    ok3 = prov.check_policy("search", {"q": untrusted}, POLICY)
    pin_ok = reg.verify("search", {"v": "1.0"})
    pin_bad = reg.verify("search", {"v": "2.0"})
    return {"user": ok1, "tool": ok2, "evil": ok3, "pin_ok": pin_ok, "pin_bad": pin_bad}

def main():
    r = run()
    assert r["user"] is True
    assert r["tool"] is True
    assert r["evil"] is False
    assert r["pin_ok"] is True
    assert r["pin_bad"] is False
    print("example_21 OK: provenance + tool pinning")

if __name__ == "__main__":
    main()
