"""Accounts merge: group accounts sharing an email.

Map each email to its first account, union accounts that share an email,
then collect and sort the emails per root component.
"""
import ast
import sys
from typing import Dict, List

UF_08_VERSION = "uf-08.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def merge_accounts(accounts: List[List[str]]) -> List[List[str]]:
    """Merge accounts that share at least one email address."""
    uf = UnionFind(len(accounts))
    owner: Dict[str, int] = {}
    for i, acc in enumerate(accounts):
        for email in acc[1:]:
            if email in owner:
                uf.union(i, owner[email])
            else:
                owner[email] = i
    groups: Dict[int, List[str]] = {}
    for email, i in owner.items():
        groups.setdefault(uf.find(i), []).append(email)
    merged = []
    for i, emails in groups.items():
        merged.append([accounts[i][0]] + sorted(emails))
    return sorted(merged)

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
    acc = [["John", "a@x", "b@x"], ["John", "b@x", "c@x"], ["Mary", "m@x"]]
    assert merge_accounts(acc) == [["John", "a@x", "b@x", "c@x"], ["Mary", "m@x"]]
    assert merge_accounts([["A", "a@x"]]) == [["A", "a@x"]]
    assert merge_accounts([]) == []
    assert merge_accounts([["A", "a@x"], ["B", "b@x"]]) == [["A", "a@x"], ["B", "b@x"]]
    assert stdlib_only()
    print("uf-08 OK")


if __name__ == "__main__":
    main()
