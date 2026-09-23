"""Unmodified baseline copy used only as the control pair."""

DECLARED_OPERATIONS = ("P", "Q", "R")


def verdict_for(operation):
    if operation == "P":
        return "accepted"
    if operation == "Q":
        return "rejected"
    if operation == "R":
        return "unknown"
    return "unknown"


def evaluate(fixture):
    operations = fixture["operations"]
    return {operation: verdict_for(operation) for operation in operations}
