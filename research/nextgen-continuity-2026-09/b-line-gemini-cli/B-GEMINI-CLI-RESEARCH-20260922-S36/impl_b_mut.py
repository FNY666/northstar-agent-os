"""S36 mutated implementation; mutation is intentionally isolated here.

Mutation point: verdict_for, R branch. Behavior diff from impl_a:
    impl_a: if operation == "R": return "unknown"
    this file: if operation == "R": return "accepted"
No fixture data or harness logic is changed by this mutation.
"""
from impl_a import DECLARED_OPERATIONS


def verdict_for(operation):
    if operation == "P":
        return "accepted"
    if operation == "Q":
        return "rejected"
    # SINGLE MUTATION: UNKNOWN -> accepted for the R branch.
    if operation == "R":
        return "accepted"
    return "unknown"


def evaluate(fixture):
    operations = fixture["operations"]
    return {operation: verdict_for(operation) for operation in operations}
