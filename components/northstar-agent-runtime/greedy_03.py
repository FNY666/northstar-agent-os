"""greedy_03: Job sequencing with deadlines.

Schedule unit-time jobs before their deadlines, highest profit first, into the latest free slot.

Time complexity: O(n * d) time
Space complexity: O(d) auxiliary
"""

import ast
import sys
GREEDY_03_VERSION = "greedy-03.v1"


def job_sequencing(jobs):
    """Return (scheduled job ids in slot order, total profit).

    jobs: iterable of (job_id, deadline, profit) with 1-based deadlines.
    """
    jobs = sorted(jobs, key=lambda j: j[2], reverse=True)
    max_d = max((j[1] for j in jobs), default=0)
    slots = [None] * (max_d + 1)
    total = 0
    for jid, deadline, profit in jobs:
        for t in range(min(deadline, max_d), 0, -1):
            if slots[t] is None:
                slots[t] = jid
                total += profit
                break
    return [s for s in slots[1:] if s is not None], total

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True



def main() -> None:
    ids, profit = job_sequencing([("a", 2, 100), ("b", 1, 19), ("c", 2, 27), ("d", 1, 25), ("e", 3, 15)])
    assert profit == 142
    assert set(ids) == {"a", "c", "e"}
    assert job_sequencing([]) == ([], 0)
    ids2, p2 = job_sequencing([("x", 1, 5)])
    assert (ids2, p2) == (["x"], 5)
    assert stdlib_only()
    print("greedy_03 OK")


if __name__ == "__main__":
    main()
