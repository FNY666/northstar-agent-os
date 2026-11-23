"""Content provenance (attest/verify/trace) interface, simulated.

Research motivation: content provenance reduces to one operational
shape. C2PA (Coalition for Content Provenance and Authenticity, the
Content Authenticity Initiative) binds a claim to an asset through
assertions: a generator declares what produced the content, each
ingredient declares what it was built from, and the claim's signature
seals the digest chain. SLSA provenance does the same for software
artifacts: a subject digest, a builder, and the materials the builder
consumed. Both reduce to one auditable primitive: *an attested
binding between a content id, a subject digest, a generator, and the
already-attested ingredients the content was derived from*.

This module is the *attestation ledger* half of that shape -- the
binding layer none of the tree's other provenance modules own
(``provenance_attestor.py`` owns the attestor-role lifecycle and
``provenance_taint.py`` owns taint propagation; this module owns the
content claim chain):

- ``Provenance.attest(content_id, subject_digest, seq, generator="",
  ingredients=())`` -- book one provenance claim: the content's
  ``sha256:`` subject pin, the generator tool that declared it, and
  the ingredient content ids it was derived from. Every ingredient
  must already be attested (fail-closed: an ingredient you cannot
  show is an ingredient you must not claim); the record is
  ``sha256:``-pinned with ``verify()``.
- ``Provenance.verify(content_id, seq)`` -- pure read view: re-walks
  the attestation chain, recomputing every digest pin and checking
  every ingredient link resolves. Integrity is *data* (``ok`` bool
  plus ``problems``), never raised.
- ``Provenance.trace(content_id, seq, max_depth=10)`` -- pure read
  view: the ancestor ingredient closure in deterministic order.
  Unknown ids yield an empty report as data, never raised.
- Views (``attestation_record`` / ``content_ids`` / ``stats`` /
  ``audit_log``) -- pure reads that validate the seq shape, consume
  nothing, and write no audit rows.
- ``provenance_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``attested`` / ``rejected``); caller-supplied seqs only. Raw
  content never crosses the audit boundary -- rows carry ids,
  digests, generator ids, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``content_id`` / ``generator`` must be non-empty str, <= 256 chars,
  no whitespace; ``generator`` may be empty (unattributed).
- ``subject_digest`` must be a ``sha256:<64hex>`` pin; ingredients
  must all name already-attested content ids (``UnknownIngredientError``)
  and may not name the content itself.
- ``attest`` on a duplicate id raises ``DuplicateContentError``; ids
  are never recycled.
- ``max_depth`` must be int (not bool), >= 1.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* provenance claims, *host-reported*
  subject digests, and *declared* generators. A booked claim means
  the host attested these bindings -- the module inspected no bytes,
  ran no generator, and proves nothing about who really made the
  content. It is an interface ledger, never a cryptographic identity.
- Digest pins prove ledger integrity and ordering, never the truth
  of the claimed provenance.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if provenance state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "provenance.v1"
SCHEMA = "northstar.provenance.v1"

KIND_ATTESTED = "attested"
KIND_REJECTED = "rejected"
_KINDS = frozenset({KIND_ATTESTED, KIND_REJECTED})

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_BANNED_DETAIL_KEYS = frozenset({
    "subject", "claim", "text", "payload", "raw", "value", "data",
    "content", "body", "artifact", "generator-secret", "key",
})


class ProvenanceError(Exception):
    """Base class for all provenance ledger errors."""


class BadIdError(ProvenanceError):
    """Malformed content id or generator id."""


class DuplicateContentError(ProvenanceError):
    """Content id already attested (ids are never recycled)."""


class UnknownContentError(ProvenanceError):
    """Content id not attested."""


class UnknownIngredientError(ProvenanceError):
    """Ingredient content id not attested."""


class BadDigestError(ProvenanceError):
    """Subject digest is not a sha256:<64hex> pin."""


class BadIngredientError(ProvenanceError):
    """Malformed ingredient list (bad id, self-reference, duplicates)."""


class BadDepthError(ProvenanceError):
    """max_depth is not a positive int."""


class SeqOrderError(ProvenanceError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(ProvenanceError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex>")
    return value


def _check_depth(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDepthError(f"max_depth must be int, got {type(value).__name__}")
    if value < 1:
        raise BadDepthError(f"max_depth must be >= 1, got {value}")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def provenance_audit_event(kind: str, detail: Dict[str, object],
                           seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the provenance ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "provenance." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


@dataclass(frozen=True)
class AttestationRecord:
    """One booked provenance claim."""
    content_id: str
    subject_digest: str
    generator: str
    ingredients: Tuple[str, ...]
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "content_id": self.content_id,
            "subject_digest": self.subject_digest,
            "generator": self.generator,
            "ingredients": list(self.ingredients),
            "digest": self.digest,
        }

    def verify(self) -> bool:
        """Recompute the record digest pin."""
        return self.digest == _digest_pin(_record_payload(self))


def _record_payload(record: AttestationRecord) -> Dict[str, object]:
    return {
        "content_id": record.content_id,
        "subject_digest": record.subject_digest,
        "generator": record.generator,
        "ingredients": list(record.ingredients),
    }


@dataclass(frozen=True)
class VerificationReport:
    """Chain integrity as data: ok bool, problems tuple."""
    content_id: str
    ok: bool
    problems: Tuple[str, ...]
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "content_id": self.content_id,
            "ok": self.ok,
            "problems": list(self.problems),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TraceReport:
    """Ancestor ingredient closure (deterministic order)."""
    content_id: str
    ancestors: Tuple[str, ...]
    depth_reached: int
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "content_id": self.content_id,
            "ancestors": list(self.ancestors),
            "depth_reached": self.depth_reached,
            "digest": self.digest,
        }


class Provenance:
    """Content provenance attestation ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._records: Dict[str, AttestationRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    # -- seq / audit plumbing ----------------------------------------

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, content_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if content_id:
            detail["content_id"] = content_id
        event = provenance_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = provenance_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    # -- core API -----------------------------------------------------

    def attest(self, content_id: str, subject_digest: str, seq: int,
               generator: str = "",
               ingredients: Tuple[str, ...] = ()) -> AttestationRecord:
        """Book one provenance claim for ``content_id``."""
        self._claim(seq)
        try:
            cid = _check_id(content_id, "content_id")
            sdigest = _check_digest(subject_digest, "subject_digest")
            gen = ""
            if generator:
                gen = _check_id(generator, "generator")
            if isinstance(ingredients, bool) or not isinstance(ingredients,
                                                                tuple):
                raise BadIngredientError("ingredients must be a tuple")
            seen = set()
            clean: Tuple[str, ...] = ()
            for ing in ingredients:
                iid = _check_id(ing, "ingredient")
                if iid in seen:
                    raise BadIngredientError(
                        f"duplicate ingredient: {iid!r}")
                seen.add(iid)
                clean = clean + (iid,)
            if cid in seen:
                raise BadIngredientError("content may not be its own ingredient")
            with self._lock:
                if cid in self._records:
                    raise DuplicateContentError(
                        f"content already attested: {cid!r}")
                for iid in clean:
                    if iid not in self._records:
                        raise UnknownIngredientError(
                            f"ingredient not attested: {iid!r}")
                clean = tuple(sorted(clean))
                digest = _digest_pin({
                    "content_id": cid,
                    "subject_digest": sdigest,
                    "generator": gen,
                    "ingredients": list(clean),
                })
                record = AttestationRecord(content_id=cid,
                                           subject_digest=sdigest,
                                           generator=gen,
                                           ingredients=clean,
                                           digest=digest)
                self._records[cid] = record
            self._emit(KIND_ATTESTED, {
                "content_id": cid,
                "subject_digest": sdigest,
                "generator": gen,
                "ingredients": list(clean),
            }, seq)
            return record
        except ProvenanceError:
            self._burn(seq, content_id if isinstance(content_id, str)
                       else "")
            raise

    def verify(self, content_id: str, seq: int) -> VerificationReport:
        """Pure read: re-walk the attestation chain; integrity as data."""
        _check_seq(seq)
        cid = _check_id(content_id, "content_id")
        with self._lock:
            if cid not in self._records:
                raise UnknownContentError(
                    f"content not attested: {cid!r}")
            problems: Tuple[str, ...] = ()
            visited = set()
            stack = [cid]
            while stack:
                cur = stack.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                rec = self._records.get(cur)
                if rec is None:
                    problems = problems + (f"dangling:{cur}",)
                    continue
                if not rec.verify():
                    problems = problems + (f"tamper:{cur}",)
                stack.extend(rec.ingredients)
            ok = not problems
            digest = _digest_pin({
                "content_id": cid,
                "ok": ok,
                "problems": list(problems),
            })
            return VerificationReport(content_id=cid, ok=ok,
                                      problems=problems, digest=digest)

    def trace(self, content_id: str, seq: int,
              max_depth: int = 10) -> TraceReport:
        """Pure read: ancestor ingredient closure; unknown is data."""
        _check_seq(seq)
        _check_depth(max_depth)
        cid = _check_id(content_id, "content_id")
        with self._lock:
            ancestors: Tuple[str, ...] = ()
            depth_reached = 0
            if cid in self._records:
                seen = {cid}
                frontier = sorted(self._records[cid].ingredients)
                depth = 1
                while frontier and depth <= max_depth:
                    depth_reached = depth
                    nxt: list = []
                    for ing in frontier:
                        if ing not in seen:
                            seen.add(ing)
                            ancestors = ancestors + (ing,)
                            rec = self._records.get(ing)
                            if rec is not None:
                                nxt.extend(rec.ingredients)
                    frontier = sorted(set(nxt))
                    depth += 1
                ancestors = tuple(sorted(set(ancestors)))
            digest = _digest_pin({
                "content_id": cid,
                "ancestors": list(ancestors),
                "depth_reached": depth_reached,
            })
            return TraceReport(content_id=cid, ancestors=ancestors,
                               depth_reached=depth_reached, digest=digest)

    # -- views --------------------------------------------------------

    def attestation_record(self, content_id: str,
                           seq: int) -> AttestationRecord:
        """Pure read of one attestation record."""
        _check_seq(seq)
        cid = _check_id(content_id, "content_id")
        with self._lock:
            if cid not in self._records:
                raise UnknownContentError(
                    f"content not attested: {cid!r}")
            return self._records[cid]

    def content_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read of all attested content ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._records))

    def stats(self, seq: int) -> Dict[str, object]:
        """Pure read ledger statistics."""
        _check_seq(seq)
        with self._lock:
            return {
                "schema": SCHEMA,
                "version": VERSION,
                "content_count": len(self._records),
                "audit_count": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """Pure read of the audit log."""
        _check_seq(seq)
        with self._lock:
            return self._audit


def main() -> None:
    prov = Provenance()
    base = _digest_pin({"file": "base-asset"})
    prov.attest("base", base, 0, generator="capture-tool")
    mid = _digest_pin({"file": "edited-asset"})
    prov.attest("edited", mid, 1, generator="edit-tool",
                ingredients=("base",))
    out = _digest_pin({"file": "published-asset"})
    prov.attest("published", out, 2, generator="publish-tool",
                ingredients=("edited",))
    report = prov.verify("published", 3)
    assert report.ok and not report.problems, report
    trace = prov.trace("published", 4)
    assert trace.ancestors == ("base", "edited"), trace
    print("provenance OK: attest, verify, trace, pins, audit")


if __name__ == "__main__":
    main()
