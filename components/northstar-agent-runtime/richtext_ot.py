"""Operational transform for a rich text editor: op bookkeeping.

Research note: operational transformation (OT) is the concurrency
control behind real-time collaborative editors (Google Docs, Etherpad,
ShareJS/ShareDB, the Jupiter and Wave systems). The core idea: instead
of locking, concurrent edits are expressed as *operations* over a
shared document, and a ``transform`` function rewrites one op against
another so both sites converge to the same document without
coordination.

The load-bearing property this module enforces is **TP1 convergence**:
for a document ``D`` and two concurrent ops ``a`` and ``b``,

    apply(apply(D, b), transform(a, b, "left"))
        == apply(apply(D, a), transform(b, a, "right"))

i.e. whichever order the ops arrive in, both sites end up with the same
text and the same attribute runs. The transform rules implemented here
are the classic text-OT rules (ShareJS/ShareDB lineage):

- insert vs insert at the same position: tie-broken by ``side``
  (``"left"`` = the transformed op's text goes first,
  ``"right"`` = it goes second);
- insert vs delete: the insert survives (it targets a gap, not the
  deleted characters);
- delete vs delete over the same characters: the second delete is a
  no-op (idempotent);
- retain vs delete: the retain over deleted text disappears;
- retain-with-attributes vs retain-with-attributes over the same range:
  attribute keys merge, conflicts resolve by ``side`` (``"left"`` = the
  transformed op's attributes win, ``"right"`` = the other op's win).

Operations are component lists over three component kinds:

- ``insert``: ``{"insert": "text", "attributes": {...}}`` — insert text
  (with optional attributes) at the cursor;
- ``retain``: ``{"retain": n, "attributes": {...}}`` — keep ``n``
  characters, optionally restyling them (an attribute value of
  ``None`` *removes* that key);
- ``delete``: ``{"delete": n}`` — drop ``n`` characters.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per document, no wall-clock, no RNG — op ids are monotonic
``op-<n>`` counters), RLock-guarded, fail-closed (malformed components,
ops that do not consume exactly the document, seq rewinds, and bad
``side`` values all raise a subclass of :class:`OTError`), stdlib-only,
``sha256:`` digest pins over type-tagged canonical encodings,
``main()`` self-check.

Honest scope: this is single-host *op bookkeeping*, not a
collaboration network. It proves that the transform rules converge
(property-tested in the test suite); it cannot transport ops, resolve
network partitions, order ops from two real clients, or prove that two
hosts applied the same op stream (GIGO, same boundary as every other
bookkeeping module). Attributes are opaque strings — the module never
interprets what "bold" means. Undo/redo, snapshots, and presence are
out of scope.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
VERSION = "richtext-ot.v1"

#: Schema pin for records produced by this module.
SCHEMA = "northstar.richtext-ot.v1"

#: Valid op component kinds.
COMPONENT_KINDS = ("insert", "retain", "delete")

#: Valid transform tie-break sides.
SIDES = ("left", "right")


class OTError(ValueError):
    """Base for all OT errors. A malformed op, not a verdict."""


class OpShapeError(OTError):
    """An op component was malformed (bad kind, bad length, bad attrs)."""


class OpLengthError(OTError):
    """An op did not consume exactly the document (or pair) it targets."""


class SeqOrderError(OTError):
    """Caller seq was not strictly increasing for this document."""


class BadSideError(OTError):
    """Transform side was not 'left' or 'right'."""


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

def _freeze_attrs(attrs: Any) -> Tuple[Tuple[str, Optional[str]], ...]:
    """Validate an attribute mapping and freeze it to sorted pairs.

    Values must be strings or None (None removes the key on apply).
    """
    if attrs is None:
        return ()
    if not isinstance(attrs, Mapping):
        raise OpShapeError(
            f"attributes must be a mapping, got {type(attrs).__name__}")
    frozen: List[Tuple[str, Optional[str]]] = []
    for key, value in attrs.items():
        if not isinstance(key, str) or not key:
            raise OpShapeError(f"attribute key must be a non-empty str, got {key!r}")
        if value is not None and not isinstance(value, str):
            raise OpShapeError(
                f"attribute value must be a str or None, got {value!r}")
        frozen.append((key, value))
    frozen.sort(key=lambda kv: kv[0])
    return tuple(frozen)


@dataclass(frozen=True)
class OpComponent:
    """One op component: insert / retain / delete.

    ``text`` is set for inserts, ``length`` for retains/deletes,
    ``attrs`` is a sorted tuple of (key, value) pairs (value ``None``
    means "remove this key" when applied by a retain).
    """
    kind: str
    text: str = ""
    length: int = 0
    attrs: Tuple[Tuple[str, Optional[str]], ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        body: Dict[str, Any] = {self.kind: self.text if self.kind == "insert"
                                else self.length}
        if self.attrs:
            body["attributes"] = {k: v for k, v in self.attrs}
        return body


@dataclass(frozen=True)
class TextOp:
    """A frozen text operation: ordered components plus a digest pin."""
    op_id: str
    seq: int
    components: Tuple[OpComponent, ...] = ()
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "op_id": self.op_id,
            "seq": self.seq,
            "components": [c.as_dict() for c in self.components],
            "digest": self.digest,
            "schema": SCHEMA,
            "version": VERSION,
        }


@dataclass(frozen=True)
class ApplyReport:
    """Record of one applied op: what changed and the digest chain link."""
    op: TextOp
    prev_digest: str
    version: int
    text: str


# ---------------------------------------------------------------------------
# op parsing / validation / normalization
# ---------------------------------------------------------------------------

def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise OTError(f"{what} must be an int, got {type(seq).__name__}")
    return seq


def _parse_component(raw: Any) -> OpComponent:
    """Parse one component from a dict or OpComponent; fail-closed."""
    if isinstance(raw, OpComponent):
        kind = raw.kind
        attrs = _freeze_attrs(dict(raw.attrs))  # re-validate hand-built pairs
        if kind == "insert":
            if not raw.text:
                raise OpShapeError("insert component needs non-empty 'text'")
            return OpComponent(kind="insert", text=raw.text, attrs=attrs)
        if kind not in ("retain", "delete"):
            raise OpShapeError(f"unknown component kind: {kind!r}")
        if isinstance(raw.length, bool) or not isinstance(raw.length, int) \
                or raw.length <= 0:
            raise OpShapeError(
                f"{kind} component needs positive int 'length', "
                f"got {raw.length!r}")
        return OpComponent(kind=kind, length=raw.length, attrs=attrs)
    if not isinstance(raw, Mapping):
        raise OpShapeError(
            f"component must be a mapping, got {type(raw).__name__}")
    kind = raw.get("kind")
    if kind not in COMPONENT_KINDS:
        raise OpShapeError(f"unknown component kind: {kind!r}")
    attrs = _freeze_attrs(raw.get("attributes"))
    if kind == "insert":
        text = raw.get("text", "")
        if not isinstance(text, str) or not text:
            raise OpShapeError("insert component needs non-empty str 'text'")
        if raw.get("length", 0):
            raise OpShapeError("insert component must not carry 'length'")
        return OpComponent(kind="insert", text=text, attrs=attrs)
    length = raw.get("length", 0)
    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise OpShapeError(
            f"{kind} component needs positive int 'length', got {length!r}")
    if raw.get("text"):
        raise OpShapeError(f"{kind} component must not carry 'text'")
    return OpComponent(kind=kind, length=length, attrs=attrs)


def _normalize(components: Sequence[OpComponent]) -> Tuple[OpComponent, ...]:
    """Merge adjacent same-kind components with identical attrs."""
    out: List[OpComponent] = []
    for comp in components:
        if (out and out[-1].kind == comp.kind and out[-1].attrs == comp.attrs
                and comp.kind != "delete"):
            prev = out[-1]
            if comp.kind == "insert":
                out[-1] = OpComponent(kind="insert",
                                     text=prev.text + comp.text,
                                     attrs=prev.attrs)
            else:  # retain
                out[-1] = OpComponent(kind="retain",
                                     length=prev.length + comp.length,
                                     attrs=prev.attrs)
        elif out and out[-1].kind == "delete" and comp.kind == "delete":
            prev = out[-1]
            out[-1] = OpComponent(kind="delete",
                                 length=prev.length + comp.length)
        else:
            out.append(comp)
    return tuple(out)


def _digest_op(op_id: str, seq: int,
               components: Sequence[OpComponent]) -> str:
    body = {
        "op_id": op_id,
        "seq": seq,
        "components": [c.as_dict() for c in components],
        "schema": SCHEMA,
        "version": VERSION,
    }
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _make_op(op_id: str, seq: int,
             components: Sequence[OpComponent]) -> TextOp:
    _check_seq(seq)
    parsed = [_parse_component(c) for c in components]
    norm = _normalize(parsed)  # may be empty: a legitimate no-op op
    return TextOp(op_id=op_id, seq=seq, components=norm,
                  digest=_digest_op(op_id, seq, norm))


# ---------------------------------------------------------------------------
# per-unit expansion (transform/compose walk one character at a time)
# ---------------------------------------------------------------------------

# A unit is [kind, payload, attrs]: insert -> [char, attrs],
# retain -> [None, attrs], delete -> [None, ()].
_Unit = List[Any]


def _expand(components: Sequence[OpComponent]) -> List[_Unit]:
    units: List[_Unit] = []
    for comp in components:
        if comp.kind == "insert":
            for ch in comp.text:
                units.append(["insert", ch, comp.attrs])
        elif comp.kind == "retain":
            for _ in range(comp.length):
                units.append(["retain", None, comp.attrs])
        else:  # delete
            for _ in range(comp.length):
                units.append(["delete", None, ()])
    return units


def _consumed(units: Sequence[_Unit]) -> int:
    """Characters of the base document the op consumes (retain+delete)."""
    return sum(1 for u in units if u[0] in ("retain", "delete"))


def _produced(units: Sequence[_Unit]) -> int:
    """Characters of the next document the op yields (retain+insert)."""
    return sum(1 for u in units if u[0] in ("retain", "insert"))


def _merge_attrs(first: Tuple[Tuple[str, Optional[str]], ...],
                 second: Tuple[Tuple[str, Optional[str]], ...],
                 first_wins: bool) -> Tuple[Tuple[str, Optional[str]], ...]:
    """Merge two attr pair-tuples; on key conflict ``first`` wins iff
    ``first_wins``, else ``second`` wins."""
    first_map = dict(first)
    second_map = dict(second)
    merged = dict(first_map)
    merged.update(second_map)
    if first_wins:
        for key in first_map:
            if key in second_map:
                merged[key] = first_map[key]
    return tuple(sorted(merged.items(), key=lambda kv: kv[0]))


def _units_to_components(units: Sequence[_Unit]) -> Tuple[OpComponent, ...]:
    comps: List[OpComponent] = []
    for kind, payload, attrs in units:
        if kind == "insert":
            comps.append(OpComponent(kind="insert", text=payload, attrs=attrs))
        elif kind == "retain":
            comps.append(OpComponent(kind="retain", length=1, attrs=attrs))
        else:
            comps.append(OpComponent(kind="delete", length=1))
    return _normalize(comps)


# ---------------------------------------------------------------------------
# transform and compose (pure functions)
# ---------------------------------------------------------------------------

def _check_side(side: Any) -> str:
    if side not in SIDES:
        raise BadSideError(f"side must be 'left' or 'right', got {side!r}")
    return side


def transform_components(a: Sequence[Any], b: Sequence[Any],
                         side: str = "left") -> Tuple[OpComponent, ...]:
    """Transform op ``a`` against concurrent op ``b``; return ``a'``.

    ``a'`` applies to the document *after* ``b`` and converges with the
    other order per TP1. Both ops must consume the same base length.

    Per-unit rules (classic text-OT, ShareJS/ShareDB lineage):

    - a's insert: emitted as-is, except it goes *after* b's insert at
      the same position when ``side == "right"`` (tie-break);
    - b's insert: ``a'`` retains over it (shifts a's later units past
      the inserted text);
    - retain/retain: retain with merged attributes (``side`` wins key
      conflicts);
    - delete/retain: the delete survives;
    - retain/delete, delete/delete: a's unit vanishes (text already
      gone / gone twice).
    """
    _check_side(side)
    A = _expand([_parse_component(c) for c in a])
    B = _expand([_parse_component(c) for c in b])
    if _consumed(A) != _consumed(B):
        raise OpLengthError(
            f"transform pair base-length mismatch: {_consumed(A)} != {_consumed(B)}")
    out: List[_Unit] = []
    i = j = 0
    a_wins_attrs = (side == "left")
    while i < len(A) or j < len(B):
        ua = A[i] if i < len(A) else None
        ub = B[j] if j < len(B) else None
        if (ua is not None and ua[0] == "insert"
                and (side == "left" or ub is None or ub[0] != "insert")):
            out.append(ua)  # a's insert (first on tie when side=left)
            i += 1
            continue
        if ub is not None and ub[0] == "insert":
            # b inserted text here: a' must retain over it so later
            # units land after the insertion (T(del,ins) shift rule).
            out.append(["retain", None, ()])
            j += 1
            continue
        if ua is None and ub is None:
            break
        if ua is None or ub is None:
            raise OpLengthError("transform pair length mismatch mid-walk")
        # both retain/delete now
        if ua[0] == "retain" and ub[0] == "retain":
            merged = _merge_attrs(ua[2], ub[2], a_wins_attrs)
            out.append(["retain", None, merged])
        elif ua[0] == "delete" and ub[0] == "retain":
            out.append(["delete", None, ()])
        # retain/delete and delete/delete: a's unit vanishes
        i += 1
        j += 1
    return _units_to_components(out)


def compose_components(a: Sequence[Any], b: Sequence[Any]) -> Tuple[OpComponent, ...]:
    """Compose sequential ops ``a`` then ``b`` into one op.

    ``b`` must consume exactly what ``a`` produces. Later op's
    attributes win on conflict.
    """
    A = _expand([_parse_component(c) for c in a])
    B = _expand([_parse_component(c) for c in b])
    if _produced(A) != _consumed(B):
        raise OpLengthError(
            f"compose pair length mismatch: produced {_produced(A)} != "
            f"consumed {_consumed(B)}")
    out: List[_Unit] = []
    i = j = 0
    while i < len(A) or j < len(B):
        ua = A[i] if i < len(A) else None
        ub = B[j] if j < len(B) else None
        if ua is not None and ua[0] == "insert":
            if ub is not None and ub[0] == "insert":
                out.append(ub)  # b's insert lands before a's text
                j += 1
                continue
            if ub is not None and ub[0] == "retain":
                merged = _merge_attrs(ua[2], ub[2], False)  # b (later op) wins
                out.append(["insert", ua[1], merged])
                i += 1
                j += 1
                continue
            if ub is not None and ub[0] == "delete":
                i += 1  # inserted then deleted: cancel
                j += 1
                continue
            out.append(ua)
            i += 1
            continue
        if ub is not None and ub[0] == "insert":
            out.append(ub)
            j += 1
            continue
        if ua is not None and ua[0] == "delete":
            out.append(ua)  # b cannot see deleted text; advance a only.
            # ub may be None here (a's trailing deletes): still valid.
            i += 1
            continue
        if ua is None and ub is None:
            break
        if ua is None or ub is None:
            raise OpLengthError("compose pair length mismatch mid-walk")
        # ua retain, ub retain/delete
        if ub[0] == "retain":
            merged = _merge_attrs(ua[2], ub[2], False)  # b (later op) wins
            out.append(["retain", None, merged])
        else:
            out.append(["delete", None, ()])
        i += 1
        j += 1
    return _units_to_components(out)


# ---------------------------------------------------------------------------
# document
# ---------------------------------------------------------------------------

class RichTextOT:
    """A rich text document with OT apply/transform/compose bookkeeping."""

    def __init__(self, text: str = "",
                 attrs: Optional[Mapping[str, str]] = None) -> None:
        if not isinstance(text, str):
            raise OpShapeError("initial text must be a str")
        base = _freeze_attrs(attrs)
        base_map = dict(base)
        self._chars: List[str] = list(text)
        self._attrs: List[Dict[str, Optional[str]]] = [
            dict(base_map) for _ in text]
        self._lock = threading.RLock()
        self._version = 0
        self._last_seq = 0
        self._counter = 0
        self._history: List[ApplyReport] = []
        self._prev_digest = "genesis"

    # -- views ----------------------------------------------------------
    @property
    def version(self) -> int:
        """Number of ops applied."""
        with self._lock:
            return self._version

    def text(self) -> str:
        """Current plain text."""
        with self._lock:
            return "".join(self._chars)

    def char_attrs(self, index: int) -> Dict[str, str]:
        """Attribute map of one character (a copy)."""
        with self._lock:
            if not 0 <= index < len(self._chars):
                raise OTError(f"char index out of range: {index}")
            return {k: v for k, v in self._attrs[index].items()
                    if v is not None}

    def segments(self) -> List[Dict[str, Any]]:
        """Merged attribute runs: [{"text": ..., "attrs": {...}}, ...]."""
        with self._lock:
            runs: List[Dict[str, Any]] = []
            for ch, attrs in zip(self._chars, self._attrs):
                clean = {k: v for k, v in attrs.items() if v is not None}
                if runs and runs[-1]["attrs"] == clean:
                    runs[-1]["text"] += ch
                else:
                    runs.append({"text": ch, "attrs": clean})
            return runs

    def history(self) -> List[Dict[str, Any]]:
        """Applied-op ledger: op ids, seqs, digests, chain links."""
        with self._lock:
            return [{
                "op_id": r.op.op_id,
                "seq": r.op.seq,
                "digest": r.op.digest,
                "prev_digest": r.prev_digest,
                "version": r.version,
            } for r in self._history]

    # -- apply ----------------------------------------------------------
    def apply(self, op: Any, seq: int) -> ApplyReport:
        """Apply an op to the document; return the frozen apply record.

        The op must consume exactly ``len(text)`` characters
        (retain + delete lengths). Fail-closed on shape, length, or
        seq-order violations.
        """
        _check_seq(seq)
        op_rec = op if isinstance(op, TextOp) else _make_op("op-?", seq, op)
        units = _expand(op_rec.components)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq {seq} not strictly increasing (last {self._last_seq})")
            if _consumed(units) != len(self._chars):
                raise OpLengthError(
                    f"op consumes {_consumed(units)} chars but document has "
                    f"{len(self._chars)}")
            cursor = 0
            for kind, payload, attrs in units:
                if kind == "insert":
                    self._chars.insert(cursor, payload)
                    self._attrs.insert(cursor, dict(attrs))
                    cursor += 1
                elif kind == "retain":
                    for key, value in attrs:
                        if value is None:
                            self._attrs[cursor].pop(key, None)
                        else:
                            self._attrs[cursor][key] = value
                    cursor += 1
                else:  # delete
                    del self._chars[cursor]
                    del self._attrs[cursor]
            self._counter += 1
            op_id = f"op-{self._counter}"
            final = TextOp(op_id=op_id, seq=seq,
                           components=op_rec.components,
                           digest=_digest_op(op_id, seq, op_rec.components))
            self._version += 1
            self._last_seq = seq
            report = ApplyReport(op=final, prev_digest=self._prev_digest,
                                 version=self._version, text=self.text())
            self._prev_digest = final.digest
            self._history.append(report)
            return report

    # -- transform / compose (pure; do not touch the document) ----------
    def transform(self, op_a: Any, op_b: Any, seq: int,
                  side: str = "left") -> TextOp:
        """Transform ``op_a`` against concurrent ``op_b``; return ``a'``.

        Pure function: the document is not modified. Both ops must
        consume the same base length.
        """
        _check_side(side)
        _check_seq(seq)
        a = op_a if isinstance(op_a, TextOp) else _make_op("a", seq, op_a)
        b = op_b if isinstance(op_b, TextOp) else _make_op("b", seq, op_b)
        comps = transform_components(a.components, b.components, side)
        op_id = f"{a.op_id}~{b.op_id}"
        return TextOp(op_id=op_id, seq=seq, components=comps,
                      digest=_digest_op(op_id, seq, comps))

    def compose(self, op_a: Any, op_b: Any, seq: int) -> TextOp:
        """Compose sequential ops ``a`` then ``b``; return one op.

        Pure function: the document is not modified. ``b`` must consume
        exactly what ``a`` produces.
        """
        _check_seq(seq)
        a = op_a if isinstance(op_a, TextOp) else _make_op("a", seq, op_a)
        b = op_b if isinstance(op_b, TextOp) else _make_op("b", seq, op_b)
        comps = compose_components(a.components, b.components)
        op_id = f"{a.op_id}+{b.op_id}"
        return TextOp(op_id=op_id, seq=seq, components=comps,
                      digest=_digest_op(op_id, seq, comps))


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

def richtext_ot_audit_event(kind: str, doc: RichTextOT,
                            op: Optional[TextOp] = None,
                            **fields: Any) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped event for an OT action."""
    if kind not in ("applied", "transformed", "composed", "rejected"):
        raise OTError(f"unknown audit kind: {kind!r}")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "version": VERSION,
        "doc_version": doc.version,
    }
    if op is not None:
        event["op_id"] = op.op_id
        event["digest"] = op.digest
    event.update(fields)
    return event


def _op_dicts(op: TextOp) -> List[Dict[str, Any]]:
    """Render a TextOp's components back to plain dicts for apply()."""
    out: List[Dict[str, Any]] = []
    for c in op.components:
        d: Dict[str, Any] = {"kind": c.kind}
        if c.kind == "insert":
            d["text"] = c.text
        else:
            d["length"] = c.length
        if c.attrs:
            d["attributes"] = dict(c.attrs)
        out.append(d)
    return out


def main() -> int:
    doc = RichTextOT("hello")
    r1 = doc.apply([{"kind": "retain", "length": 5},
                    {"kind": "insert", "text": " world"}], seq=1)
    assert r1.text == "hello world", r1.text
    assert r1.op.op_id == "op-1"
    assert doc.version == 1

    # concurrent pair: a inserts at 0, b deletes first char
    a = [{"kind": "insert", "text": ">>"},
         {"kind": "retain", "length": 11}]
    b = [{"kind": "delete", "length": 1},
         {"kind": "retain", "length": 10}]
    a_prime = doc.transform(a, b, seq=2, side="left")
    b_prime = doc.transform(b, a, seq=3, side="right")
    left = RichTextOT("hello world")
    left.apply(b, seq=1)
    left.apply(_op_dicts(a_prime), seq=2)
    right = RichTextOT("hello world")
    right.apply(a, seq=1)
    right.apply(_op_dicts(b_prime), seq=2)
    assert left.text() == right.text() == ">>ello world", (left.text(), right.text())

    # compose: sequential apply == composed apply
    d1 = RichTextOT("abc")
    op1 = [{"kind": "retain", "length": 1},
           {"kind": "insert", "text": "X"},
           {"kind": "retain", "length": 2}]
    op2 = [{"kind": "retain", "length": 2},
           {"kind": "delete", "length": 1},
           {"kind": "retain", "length": 1}]
    d1.apply(op1, seq=1)
    d1.apply(op2, seq=2)
    composed = doc.compose(op1, op2, seq=4)
    d2 = RichTextOT("abc")
    d2.apply(_op_dicts(composed), seq=1)
    assert d1.text() == d2.text() == "aXc", (d1.text(), d2.text())

    # attributes
    d3 = RichTextOT("hi")
    d3.apply([{"kind": "retain", "length": 2,
               "attributes": {"bold": "true"}}], seq=1)
    assert d3.segments() == [{"text": "hi", "attrs": {"bold": "true"}}]
    print("richtext-ot OK: apply, transform converge, compose, attributes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
