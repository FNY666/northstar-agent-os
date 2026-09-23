#!/usr/bin/env python3
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
"""Independent local implementation B for synthetic S35."""
KNOWN = {"P": 1, "Q": 2, "R": 3}


def evaluate_event(event):
    # Deliberately separate control flow/data representation from impl-A.
    code = KNOWN.get(event.get("op_id"), 0)
    if code == 0 or event.get("revoked", False):
        return "UNKNOWN"
    anomaly = event.get("anomaly")
    if anomaly is not None and anomaly in ("duplicate", "out_of_order", "missing"):
        return "UNKNOWN"
    form = (event.get("kind"), event.get("payload"))
    table = {
        ("apply", "valid"): "accepted",
        ("reject", "valid"): "rejected",
    }
    return table.get(form, "UNKNOWN")


def evaluate_fixture(fixture):
    out = {}
    for event in fixture["events"]:
        out[event["event_id"]] = evaluate_event(event)
    return out
