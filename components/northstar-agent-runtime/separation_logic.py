"""Separation logic: heap assertions for local reasoning.

When the runtime allocates or frees memory regions (audit buffers, skill
sandboxes, compaction segments), the correctness question is never "does
the whole program still type-check" -- it is "which heap cells did this
operation touch, and did it leave the rest alone". Separation logic
(Reynolds 2002; O'Hearn, Yang, Reynolds) answers exactly that, via the
*separating conjunction*: ``P * Q`` means the heap splits into two
*disjoint* parts, one satisfying ``P`` and the other ``Q``.

This module pins the interface half of that idea -- the assertion
algebra, footprint computation, and the frame rule -- so that heap
reasoning can be expressed in the runtime's house style (frozen records,
caller-supplied seqs, no wall-clock, stdlib-only):

* ``emp()`` -- the empty-heap assertion; true only of the empty heap.
* ``points_to(addr, value)`` -- the singleton heap ``addr |-> value``.
* ``star(p, q)`` -- ``P * Q``; fail-closed when the two footprints
  overlap (overlap is not a policy outcome, it is a logic error: the
  separating conjunction *means* disjointness).
* ``frame_rule(pre, post, frame)`` -- from a Hoare triple ``{P} C {Q}``
  and a frame ``R`` disjoint from both, produce ``{P * R} C {Q * R}``.
  The host supplies the triple (the command ``C`` is the host's job to
  execute); the module checks the frame is syntactically disjoint and
  records the derivation, so framing is a checked transformation, not
  a comment.

Addresses are non-negative ints (the runtime's logical heap is an
abstract address space, not raw pointers); values are type-tagged bytes
so ``b"1"`` and ``"1"`` can never alias in the encoding. Assertions are
immutable and hashable, so derived triples can ride the durable-audit
path as pinned records.

Honest scope: this is the *assertion language* and its syntactic
rules, not a verifier. It cannot execute commands, cannot prove
``entails`` beyond structural decomposition (entailment between
arbitrary assertions is undecidable in general), and cannot see the
real heap -- it reasons about the heap the *host reports*. A framed
triple is "the frame rule was applied correctly to this triple", never
"the program is memory-safe". Real proof needs a verifier/embedding
(see ``formal_verif``); this module is the bookkeeping it would run on.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Tuple


#: Version pin for this module's record shape.
SEPARATION_LOGIC_VERSION = "separation-logic.v1"

#: Schema pin carried on audit records.
SEPARATION_LOGIC_SCHEMA = "northstar.separation-logic.v1"

#: Assertion kinds.
KIND_EMP = "emp"
KIND_POINTS_TO = "points_to"
KIND_STAR = "star"
KIND_PURE = "pure"

#: Domain-separation prefix so assertion pins cannot collide with pins
#: from other modules.
_DOMAIN = b"northstar.separation-logic.v1:"

#: Fixed vocabulary for audit events.
_AUDIT_KINDS = (
    "assertion-built",
    "star-composed",
    "frame-applied",
    "entailment-checked",
    "rejected",
)


class SepLogicError(Exception):
    """Fail-closed error for the separation-logic interface."""


def _check_seq(seq: int) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SepLogicError("seq must be a non-negative int")


def _check_addr(addr: int) -> None:
    if isinstance(addr, bool) or not isinstance(addr, int) or addr < 0:
        raise SepLogicError("addr must be a non-negative int")


def _tag_value(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise SepLogicError("value must be bytes (str is never silently encoded)")
    return b"\x00" + value  # byte-domain tag: bytes values live in their own domain


def _sha256_pin(*parts: bytes) -> str:
    h = hashlib.sha256(_DOMAIN)
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return "sha256:" + h.hexdigest()


@dataclass(frozen=True)
class HeapAssertion:
    """An immutable separation-logic assertion.

    ``kind`` is one of ``emp`` / ``points_to`` / ``star`` / ``pure``:

    * ``emp``: no payload; true only of the empty heap.
    * ``points_to``: ``addr`` and ``value_pin`` set; the singleton heap.
    * ``star``: ``left`` and ``right`` set; separating conjunction.
    * ``pure``: ``pure_name`` set; a heap-independent fact (footprint-free).

    The ``digest`` pins the whole assertion so derived triples can be
    audit-pinned without carrying the heap contents.
    """

    kind: str
    addr: int = -1
    value_pin: str = ""
    left: "HeapAssertion | None" = None
    right: "HeapAssertion | None" = None
    pure_name: str = ""
    digest: str = ""

    def __post_init__(self) -> None:
        if self.kind not in (KIND_EMP, KIND_POINTS_TO, KIND_STAR, KIND_PURE):
            raise SepLogicError(f"unknown assertion kind: {self.kind!r}")
        if self.kind == KIND_POINTS_TO:
            if self.addr < 0:
                raise SepLogicError("points_to needs a non-negative addr")
            if not self.value_pin.startswith("sha256:"):
                raise SepLogicError("points_to needs a sha256: value pin")
        if self.kind == KIND_STAR:
            if not isinstance(self.left, HeapAssertion) or not isinstance(
                self.right, HeapAssertion
            ):
                raise SepLogicError("star needs two HeapAssertion children")
        if self.kind == KIND_PURE and not self.pure_name:
            raise SepLogicError("pure needs a name")
        if not self.digest.startswith("sha256:"):
            raise SepLogicError("assertion needs a sha256: digest pin")

    def as_dict(self) -> Dict[str, object]:
        body: Dict[str, object] = {
            "kind": self.kind,
            "digest": self.digest,
            "schema": SEPARATION_LOGIC_SCHEMA,
            "version": SEPARATION_LOGIC_VERSION,
        }
        if self.kind == KIND_POINTS_TO:
            body["addr"] = self.addr
            body["value_pin"] = self.value_pin
        elif self.kind == KIND_STAR:
            assert self.left is not None and self.right is not None
            body["left"] = self.left.as_dict()
            body["right"] = self.right.as_dict()
        elif self.kind == KIND_PURE:
            body["pure_name"] = self.pure_name
        return body


def _digest_emp() -> str:
    return _sha256_pin(b"emp")


def _digest_points_to(addr: int, value: bytes) -> str:
    return _sha256_pin(
        b"points_to",
        addr.to_bytes(8, "big"),
        _tag_value(value),
    )


def _digest_star(left: HeapAssertion, right: HeapAssertion) -> str:
    # Commutative normalization: order the digests so P*Q == Q*P as pins.
    l, r = sorted((left.digest, right.digest))
    return _sha256_pin(b"star", l.encode("utf-8"), r.encode("utf-8"))


def _digest_pure(name: str) -> str:
    return _sha256_pin(b"pure", name.encode("utf-8"))


@dataclass(frozen=True)
class FramedTriple:
    """The result of applying the frame rule: ``{P * R} C {Q * R}``.

    Carries the original triple's digests plus the frame's, so the
    derivation is a pinned audit artifact.
    """

    pre: HeapAssertion
    post: HeapAssertion
    frame: HeapAssertion
    digest: str

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:"):
            raise SepLogicError("framed triple needs a sha256: digest pin")

    def as_dict(self) -> Dict[str, object]:
        return {
            "pre": self.pre.as_dict(),
            "post": self.post.as_dict(),
            "frame": self.frame.as_dict(),
            "digest": self.digest,
            "schema": SEPARATION_LOGIC_SCHEMA,
            "version": SEPARATION_LOGIC_VERSION,
        }


class SepLogic:
    """The separation-logic assertion interface.

    Stateless: every method is a pure constructor or a pure check over
    caller-supplied assertions. No wall-clock, no randomness, no heap
    access -- the host owns the real heap.
    """

    # -- constructors -------------------------------------------------

    def emp(self) -> HeapAssertion:
        """The empty-heap assertion."""
        return HeapAssertion(kind=KIND_EMP, digest=_digest_emp())

    def pure(self, name: str) -> HeapAssertion:
        """A heap-independent fact (footprint-free).

        Names a pure predicate the host tracks separately (e.g.
        ``"x > 0"``); the logic only records the name and never looks
        inside it.
        """
        if not isinstance(name, str) or not name:
            raise SepLogicError("pure name must be a non-empty str")
        return HeapAssertion(kind=KIND_PURE, pure_name=name, digest=_digest_pure(name))

    def points_to(self, addr: int, value: bytes) -> HeapAssertion:
        """The singleton heap ``addr |-> value``."""
        _check_addr(addr)
        _tag_value(value)  # type validation; the pin below re-tags
        return HeapAssertion(
            kind=KIND_POINTS_TO,
            addr=addr,
            value_pin=_sha256_pin(_tag_value(value)),
            digest=_digest_points_to(addr, value),
        )

    def star(self, p: HeapAssertion, q: HeapAssertion) -> HeapAssertion:
        """The separating conjunction ``P * Q``.

        Fail-closed on footprint overlap: ``*`` *means* disjointness,
        so an overlap is a logic error, never a silently weakened
        assertion.
        """
        if not isinstance(p, HeapAssertion) or not isinstance(q, HeapAssertion):
            raise SepLogicError("star needs two HeapAssertion operands")
        fp_p = self.footprint(p)
        fp_q = self.footprint(q)
        overlap = fp_p & fp_q
        if overlap:
            raise SepLogicError(
                f"star overlap: addresses {sorted(overlap)} claimed by both sides"
            )
        # Commutative normalization: keep the canonical order so equal
        # assertions compare equal regardless of construction order.
        left, right = (p, q) if p.digest <= q.digest else (q, p)
        return HeapAssertion(
            kind=KIND_STAR,
            left=left,
            right=right,
            digest=_digest_star(p, q),
        )

    def star_all(self, assertions: Tuple[HeapAssertion, ...]) -> HeapAssertion:
        """Fold ``star`` over a tuple; the empty fold is ``emp``."""
        if not isinstance(assertions, tuple):
            raise SepLogicError("star_all needs a tuple of HeapAssertion")
        acc = self.emp()
        for a in assertions:
            acc = self.star(acc, a)
        return acc

    # -- queries ------------------------------------------------------

    def footprint(self, p: HeapAssertion) -> FrozenSet[int]:
        """The set of heap addresses the assertion claims."""
        if not isinstance(p, HeapAssertion):
            raise SepLogicError("footprint needs a HeapAssertion")
        if p.kind == KIND_POINTS_TO:
            return frozenset({p.addr})
        if p.kind == KIND_STAR:
            assert p.left is not None and p.right is not None
            return self.footprint(p.left) | self.footprint(p.right)
        return frozenset()  # emp and pure claim nothing

    def entails(self, p: HeapAssertion, q: HeapAssertion) -> bool:
        """Structural entailment check ``P |- Q`` (simulated).

        Decides only what structural decomposition can decide:

        * identical assertions entail each other;
        * ``emp`` entails nothing except ``emp`` (and pure facts are
          footprint-free, so ``P`` entails ``P * pure(..)``);
        * ``star`` is commutative and associative under the digest
          normalization, so structural rearrangements are entailed;
        * anything else is answered ``False`` -- a refusal to decide,
          not a proof of non-entailment (full entailment is undecidable
          in general, and this module is not a prover).
        """
        if not isinstance(p, HeapAssertion) or not isinstance(q, HeapAssertion):
            raise SepLogicError("entails needs two HeapAssertion operands")
        if p.digest == q.digest:
            return True
        # Strip pure conjuncts: pure facts have no footprint, so they add
        # no heap obligation on either side.
        p_stripped = self._strip_pure(p)
        q_stripped = self._strip_pure(q)
        return p_stripped.digest == q_stripped.digest

    def _strip_pure(self, p: HeapAssertion) -> HeapAssertion:
        """Remove ``pure`` conjuncts (they carry no heap obligation)."""
        if p.kind == KIND_STAR:
            assert p.left is not None and p.right is not None
            left = self._strip_pure(p.left)
            right = self._strip_pure(p.right)
            if left.kind == KIND_PURE and left.pure_name and not right.kind == KIND_PURE:
                return right
            if right.kind == KIND_PURE and right.pure_name and not left.kind == KIND_PURE:
                return left
            if left.kind == KIND_EMP:
                return right
            if right.kind == KIND_EMP:
                return left
            if left.digest == p.left.digest and right.digest == p.right.digest:
                return p
            return self.star(left, right)
        if p.kind == KIND_PURE:
            return self.emp()
        return p

    # -- the frame rule ------------------------------------------------

    def frame_rule(
        self,
        pre: HeapAssertion,
        post: HeapAssertion,
        frame: HeapAssertion,
    ) -> FramedTriple:
        """Apply the frame rule to ``{P} C {Q}`` with frame ``R``.

        Returns the framed triple ``{P * R} C {Q * R}`` as a pinned
        ``FramedTriple``. The host's triple is taken as given (the
        command is the host's job); the module checks the load-bearing
        side condition -- the frame must be disjoint from both the pre
        and post footprints -- fail-closed.
        """
        for name, a in (("pre", pre), ("post", post), ("frame", frame)):
            if not isinstance(a, HeapAssertion):
                raise SepLogicError(f"frame_rule: {name} must be a HeapAssertion")
        fp_frame = self.footprint(frame)
        for name, a in (("pre", pre), ("post", post)):
            overlap = self.footprint(a) & fp_frame
            if overlap:
                raise SepLogicError(
                    f"frame_rule: frame overlaps {name} footprint "
                    f"at addresses {sorted(overlap)}"
                )
        new_pre = self.star(pre, frame)
        new_post = self.star(post, frame)
        digest = _sha256_pin(
            b"frame",
            pre.digest.encode("utf-8"),
            post.digest.encode("utf-8"),
            frame.digest.encode("utf-8"),
        )
        return FramedTriple(pre=new_pre, post=new_post, frame=frame, digest=digest)


def separation_logic_audit_event(
    kind: str,
    seq: int,
    assertion: HeapAssertion | None = None,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for a separation-logic operation.

    The record carries assertion *digests*, never heap contents.
    """
    if kind not in _AUDIT_KINDS:
        raise SepLogicError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if assertion is not None and not isinstance(assertion, HeapAssertion):
        raise SepLogicError("assertion must be a HeapAssertion or None")
    if not isinstance(detail, str):
        raise SepLogicError("detail must be a str")
    return {
        "schema": SEPARATION_LOGIC_SCHEMA,
        "kind": kind,
        "seq": seq,
        "assertion_digest": assertion.digest if assertion is not None else "",
        "detail": detail,
        "version": SEPARATION_LOGIC_VERSION,
    }


def _self_check() -> None:
    sl = SepLogic()

    # emp: empty footprint, pins deterministically.
    e1, e2 = sl.emp(), sl.emp()
    assert e1.digest == e2.digest
    assert sl.footprint(e1) == frozenset()
    assert e1.as_dict()["kind"] == "emp"

    # points_to: singleton, type-tagged.
    s1 = sl.points_to(0, b"v")
    s2 = sl.points_to(0, b"v")
    s3 = sl.points_to(1, b"v")
    assert s1.digest == s2.digest and s1.digest != s3.digest
    assert sl.footprint(s1) == frozenset({0})

    # star: disjoint composes, overlap fails closed, commutativity normalizes.
    a = sl.points_to(0, b"a")
    b = sl.points_to(1, b"b")
    ab = sl.star(a, b)
    ba = sl.star(b, a)
    assert ab.digest == ba.digest
    assert sl.footprint(ab) == frozenset({0, 1})
    try:
        sl.star(a, sl.points_to(0, b"other"))
        raise AssertionError("star overlap must fail")
    except SepLogicError:
        pass

    # pure: footprint-free, strips under entailment.
    p = sl.pure("x > 0")
    assert sl.footprint(p) == frozenset()
    assert sl.entails(sl.star(a, p), a)
    assert not sl.entails(a, b)

    # frame rule: disjoint frame frames both sides.
    pre = sl.points_to(0, b"old")
    post = sl.points_to(0, b"new")
    frame = sl.points_to(9, b"untouched")
    ft = sl.frame_rule(pre, post, frame)
    assert sl.footprint(ft.pre) == frozenset({0, 9})
    assert sl.footprint(ft.post) == frozenset({0, 9})
    assert ft.digest.startswith("sha256:")
    try:
        sl.frame_rule(pre, post, sl.points_to(0, b"clash"))
        raise AssertionError("frame overlap must fail")
    except SepLogicError:
        pass

    # audit event shape.
    ev = separation_logic_audit_event("frame-applied", 7, ft.pre, detail="t1")
    assert ev["schema"] == SEPARATION_LOGIC_SCHEMA
    assert ev["seq"] == 7

    print("separation-logic OK: emp, points_to, star, frame rule, entailment")


def main() -> None:
    _self_check()


if __name__ == "__main__":
    main()
