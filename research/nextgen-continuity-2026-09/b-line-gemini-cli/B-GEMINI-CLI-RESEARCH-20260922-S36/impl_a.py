"""S36 synthetic baseline implementation.

Declared operations are P, Q, and R. X is intentionally undeclared and
therefore conservative UNKNOWN.
"""
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
