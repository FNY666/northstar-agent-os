"""Example 01: Tag tool output with provenance, then spotlight-mark it.
Modules demonstrated: provenance_tagging + spotlighting
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
spot = _load("spotlighting")

POLICY = {"send_email": {"allowed_sources": {"user"}}}

def run():
    raw = "Search result: the meeting is at 3pm."
    tagged = prov.tag_tool_output(raw, "web_search")
    marked, nonce = spot.spotlight(tagged.value, level="delimit")
    # Provenance policy: tool output cannot feed send_email.
    allowed = prov.check_policy("send_email", {"body": tagged}, POLICY)
    user_tag = prov.tag_user("please summarize")
    user_ok = prov.check_policy("send_email", {"body": user_tag}, POLICY)
    return {"nonce": nonce, "nonce_in_marked": nonce in marked,
            "tool_denied": not allowed, "user_allowed": user_ok}

def main():
    r = run()
    assert r["nonce"]
    assert r["nonce_in_marked"] is True
    assert r["tool_denied"] is True
    assert r["user_allowed"] is True
    assert prov.stdlib_only() and spot.stdlib_only()
    print("example_01 OK: provenance + spotlighting")

if __name__ == "__main__":
    main()
