#!/usr/bin/env python3
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
"""Independent local implementation A for synthetic S35."""
DECLARED = frozenset(("P", "Q", "R"))


def evaluate_event(event):
    """Return exactly one conservative three-state verdict."""
    op = event.get("op_id")
    if op not in DECLARED:
        return "UNKNOWN"
    if event.get("revoked") is True:
        return "UNKNOWN"
    if event.get("anomaly") in {"duplicate", "out_of_order", "missing"}:
        return "UNKNOWN"
    if event.get("kind") not in {"apply", "reject"}:
        return "UNKNOWN"
    if event.get("payload") != "valid":
        return "UNKNOWN"
    return "accepted" if event["kind"] == "apply" else "rejected"


def evaluate_fixture(fixture):
    return {e["event_id"]: evaluate_event(e) for e in fixture["events"]}
