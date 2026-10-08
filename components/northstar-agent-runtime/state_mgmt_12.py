"""State 12: operational transformation (mock), Simulated.

Mock OT for collaborative editing of a shared string:
- ops: insert(pos, text), delete(pos, length)
- transform(op_a, op_b): adjust op_a against concurrent op_b
- apply(doc, ops): apply in order

Covers the core transform cases: insert/insert (tie-break by site id),
insert/delete, delete/delete (overlap clamps).

Fail-closed: out-of-range positions, negative lengths raise.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List

MODULE_VERSION = "state-mgmt-12.v1"
SCHEMA_PIN = "northstar.state-mgmt-12.v1"


class OTError(Exception):
    pass


@dataclass
class Op:
    kind: str  # "insert" | "delete"
    pos: int
    text: str = ""  # insert
    length: int = 0  # delete
    site: int = 0  # tie-breaker


def _check(op: Op, doc_len: int) -> None:
    if op.kind not in ("insert", "delete"):
        raise OTError(f"bad kind {op.kind!r}")
    if op.pos < 0 or op.pos > doc_len:
        raise OTError(f"pos {op.pos} out of range (len {doc_len})")
    if op.kind == "delete":
        if op.length < 0:
            raise OTError("length must be >= 0")
        if op.pos + op.length > doc_len:
            raise OTError("delete extends past end")


def transform(a: Op, b: Op) -> Op:
    """Transform a against concurrent b (b already applied)."""
    if b.kind == "insert":
        if b.pos < a.pos or (b.pos == a.pos and b.site < a.site):
            shift = len(b.text) if a.kind == "insert" else len(b.text)
            return Op(a.kind, a.pos + shift, a.text, a.length, a.site)
        return a
    # b is delete
    b_end = b.pos + b.length
    if a.kind == "insert":
        if a.pos <= b.pos:
            return a
        if a.pos >= b_end:
            return Op(a.kind, a.pos - b.length, a.text, a.length, a.site)
        return Op(a.kind, b.pos, a.text, a.length, a.site)  # landed inside
    # a is delete
    a_end = a.pos + a.length
    if a_end <= b.pos:
        return a
    if a.pos >= b_end:
        return Op(a.kind, a.pos - b.length, a.text, a.length, a.site)
    # overlap: clamp
    new_pos = min(a.pos, b.pos)
    new_end = max(a_end, b_end) - b.length
    return Op("delete", new_pos, "", max(0, new_end - new_pos), a.site)


def apply(doc: str, ops: List[Op]) -> str:
    for op in ops:
        _check(op, len(doc))
        if op.kind == "insert":
            doc = doc[:op.pos] + op.text + doc[op.pos:]
        else:
            doc = doc[:op.pos] + doc[op.pos + op.length:]
    return doc


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    # Concurrent inserts at same pos: site id tie-break converges.
    a = Op("insert", 1, "X", site=1)
    b = Op("insert", 1, "Y", site=2)
    doc = "ab"
    # Site 1 applies a then transformed b; site 2 applies b then transformed a.
    r1 = apply(apply(doc, [a]), [transform(b, a)])
    r2 = apply(apply(doc, [b]), [transform(a, b)])
    assert r1 == r2 == "aXYb", (r1, r2)
    # Insert vs delete.
    d = Op("delete", 0, length=1)
    ins = Op("insert", 2, "Z")
    assert apply("abc", [d, transform(ins, d)]) == "bZc"
    # Overlapping deletes clamp.
    d1 = Op("delete", 0, length=2)
    d2 = Op("delete", 1, length=2)
    r = apply(apply("abcd", [d1]), [transform(d2, d1)])
    assert r == "d", r
    # Out of range -> fail-closed.
    try:
        apply("ab", [Op("insert", 9, "x")])
        raise AssertionError("should raise")
    except OTError:
        pass
    assert stdlib_only()
    print("state_mgmt_12 OK: OT transforms converge, fail-closed")


if __name__ == "__main__":
    main()
