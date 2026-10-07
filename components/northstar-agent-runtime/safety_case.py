"""Safety-case (claim/evidence/argument) interface, simulated.

Research motivation: safety cases are the assurance workhorse in
high-integrity engineering -- UK nuclear and rail, UL 4600, and the
frontier-AI safety-case literature all reduce to the same ledger:
declare a top-level safety claim, decompose it into sub-claims with a
pinned argumentation strategy, bind evidence items (tests, evals,
proofs, reviews, monitors, assumptions) to the claims they support,
and derive an argument status that is recomputable from the booked
records. Getting the bookkeeping wrong (orphaned claims, double-bound
evidence, silent strategy drift, unverifiable verdicts) corrupts the
assurance argument before any safety claim is made.

This module is the *decision ledger* half of that shape:

- ``SafetyCase.claim(claim_id, statement_digest, seq, parent_id="")``
  -- declare one claim; the statement travels as a ``sha256:`` digest
  pin, raw text never enters a record. ``parent_id`` names an already
  declared claim and forms the decomposition tree (roots have no
  parent; cycles are impossible because parents must pre-exist).
  Returns a frozen ``ClaimRecord``. Duplicate ids are refused
  fail-closed; ids are never recycled.
- ``SafetyCase.evidence(claim_id, evidence_id, seq,
  evidence_digest="", kind="test")`` -- bind one evidence item to a
  claim over the pinned kind vocabulary. Returns a frozen
  ``EvidenceRecord`` with a minted ``ev-N`` binding id. Duplicate
  (claim, evidence) bindings and bindings to retired claims are
  refused fail-closed.
- ``SafetyCase.argue(claim_id, seq)`` -- pure read view deriving the
  argument status for a claim and its whole subtree: a leaf claim is
  ``supported`` with >= 1 bound evidence item, ``open`` otherwise; a
  decomposed claim is ``supported`` when every child is supported,
  ``partial`` otherwise. Validates seq shape, consumes nothing,
  writes no audit row. Returns a frozen ``ArgumentReport`` with a
  ``sha256:`` digest pin.
- ``SafetyCase.retire(claim_id, seq, reason="manual")`` -- terminal:
  the claim is retired forever; later mutations touching it are
  refused fail-closed. Returns a frozen ``RetireRecord``.
- ``safety_case_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``claim-declared`` / ``evidence-bound`` / ``retired`` /
  ``rejected``); caller-supplied seqs only. Raw statements and raw
  evidence never cross the audit boundary -- audit rows carry ids,
  kinds, counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``claim_id`` / ``evidence_id`` must be non-empty str, <= 256 chars,
  no whitespace (bool refused).
- ``statement_digest`` must be a ``sha256:``-prefixed pin (raw
  statements never enter a record); ``evidence_digest`` may be empty
  (evidence pending) or a valid ``sha256:`` pin.
- ``kind`` must name the pinned evidence-kind vocabulary;
  ``reason`` must name the pinned retire-reason vocabulary.
- ``parent_id`` must name an already declared, non-retired claim.
- Binding evidence to a retired claim raises ``RetiredClaimError``.
- Arguing a retired claim raises ``RetiredClaimError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* claims and *host-reported* evidence
  bindings. A ``supported`` verdict means "the booked evidence and
  decomposition agree the claim is argued", never that the claim is
  true -- bindings are GIGO: the module cannot prove the evidence
  exists, ran, or measured honestly.
- ``argue()`` derives verdicts deterministically from the ledger;
  the derivation is recomputable (``verify()``) but proves nothing
  about the real world.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if safety state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj):  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
SAFETY_CASE_VERSION = "safety-case.v1"

#: Schema pin carried by records and audit events.
SAFETY_CASE_SCHEMA = "northstar.safety-case.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned evidence-kind vocabulary.
KIND_TEST = "test"
KIND_EVAL = "eval"
KIND_PROOF = "proof"
KIND_REVIEW = "review"
KIND_MONITOR = "monitor"
KIND_ASSUMPTION = "assumption"
EVIDENCE_KINDS = (KIND_TEST, KIND_EVAL, KIND_PROOF, KIND_REVIEW,
                  KIND_MONITOR, KIND_ASSUMPTION)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_INVALIDATED = "invalidated"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED, REASON_INVALIDATED)

#: Pinned argument-verdict vocabulary.
VERDICT_SUPPORTED = "supported"
VERDICT_PARTIAL = "partial"
VERDICT_OPEN = "open"
VERDICTS = (VERDICT_SUPPORTED, VERDICT_PARTIAL, VERDICT_OPEN)

#: Audit event kinds.
KIND_CLAIM_DECLARED = "claim-declared"
KIND_EVIDENCE_BOUND = "evidence-bound"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CLAIM_DECLARED, KIND_EVIDENCE_BOUND, KIND_RETIRED,
          KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"statement", "evidence", "payload", "value", "raw", "text", "data",
     "variables"})

#: Max id length.
_MAX_ID_LEN = 256


class SafetyCaseError(Exception):
    """Base error for the safety-case ledger (programming errors)."""


class BadClaimError(SafetyCaseError):
    """Raised when a claim id is malformed."""


class DuplicateClaimError(SafetyCaseError):
    """Raised when a claim id is declared twice."""


class UnknownClaimError(SafetyCaseError):
    """Raised when a claim id names no declared claim."""


class RetiredClaimError(SafetyCaseError):
    """Raised when a claim id names a retired claim."""


class BadDigestError(SafetyCaseError):
    """Raised when a digest pin is malformed."""


class BadEvidenceError(SafetyCaseError):
    """Raised when an evidence id is malformed."""


class DuplicateEvidenceError(SafetyCaseError):
    """Raised when a (claim, evidence) binding already exists."""


class BadEvidenceKindError(SafetyCaseError):
    """Raised when an evidence kind is outside the pinned vocabulary."""


class BadReasonError(SafetyCaseError):
    """Raised when a retire reason is outside the pinned vocabulary."""


class SeqOrderError(SafetyCaseError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(SafetyCaseError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value, name="seq"):
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value, kind):
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    err = BadClaimError if kind == "claim" else BadEvidenceError
    if isinstance(value, bool) or not isinstance(value, str):
        raise err(f"{kind}_id must be str, got {type(value).__name__}")
    if not value:
        raise err(f"{kind}_id must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise err(f"{kind}_id too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise err(f"{kind}_id must not contain whitespace")
    return value


def _check_digest(digest, name, required):
    """Validate a digest pin: 'sha256:'-prefixed (empty iff not required)."""
    if not digest:
        if required:
            raise BadDigestError(f"{name} is required")
        return ""
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError(
            f"{name} must be str, got {type(digest).__name__}")
    if not digest.startswith("sha256:") or len(digest) <= len("sha256:"):
        raise BadDigestError(f"{name} must be a sha256:-prefixed digest pin")
    return digest


def _check_evidence_kind(kind):
    """Validate an evidence kind against the pinned vocabulary."""
    if kind not in EVIDENCE_KINDS:
        raise BadEvidenceKindError(
            f"kind must be one of {list(EVIDENCE_KINDS)}, got {kind!r}")
    return kind


def _check_retire_reason(reason):
    """Validate a retire reason against the pinned vocabulary."""
    if reason not in RETIRE_REASONS:
        raise BadReasonError(
            f"reason must be one of {list(RETIRE_REASONS)}, got {reason!r}")
    return reason


def _pin(*parts):
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": SAFETY_CASE_SCHEMA,
        "parts": list(parts),
    })


def safety_case_audit_event(kind, detail, seq):
    """Build one ``audit.ndjson/1`` audit row for the safety ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": SAFETY_CASE_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ClaimRecord:
    """Frozen record of one declared safety claim."""
    claim_id: str
    parent_id: str
    statement_digest: str
    seq: int
    digest: str

    def verify(self, claim_id, parent_id, statement_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("claim", claim_id, parent_id,
                                   statement_digest, self.seq)


@dataclass(frozen=True)
class EvidenceRecord:
    """Frozen record of one (claim, evidence) binding."""
    binding_id: str
    claim_id: str
    evidence_id: str
    kind: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, binding_id, claim_id, evidence_id, kind,
               evidence_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("evidence", binding_id, claim_id,
                                   evidence_id, kind, evidence_digest,
                                   self.seq)


@dataclass(frozen=True)
class ArgumentReport:
    """Pure read view: derived argument status for one claim subtree."""
    claim_id: str
    # Verdict is data: supported / partial / open.
    verdict: str
    evidence_count: int
    # Direct children, sorted, with their derived verdicts.
    child_ids: Tuple[str, ...]
    child_verdicts: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, claim_id, verdict, evidence_count, child_ids,
               child_verdicts):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("argue", claim_id, verdict,
                                   evidence_count, list(child_ids),
                                   list(child_verdicts), self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of one claim retirement (terminal)."""
    claim_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, claim_id, reason):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", claim_id, reason, self.seq)


@dataclass(frozen=True)
class StatsReport:
    """Pure read view: ledger population counts as data."""
    claims: int
    evidence_bindings: int
    retired: int


class SafetyCase:
    """Deterministic safety-case decision ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._claims: Dict[str, ClaimRecord] = {}
        self._children: Dict[str, list] = {}
        self._bindings: Dict[str, EvidenceRecord] = {}
        self._binding_keys: set = set()
        self._retired: set = set()
        self._binding_counter = 0
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq):
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq, error):
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(safety_case_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind, detail, seq):
        self._audit.append(safety_case_audit_event(audit_kind, detail, seq))

    # -- internal helpers -------------------------------------------------

    def _require_live(self, claim_id):
        """Return nothing; raise for unknown or retired claims."""
        if claim_id not in self._claims:
            raise UnknownClaimError(f"unknown claim: {claim_id!r}")
        if claim_id in self._retired:
            raise RetiredClaimError(f"claim retired: {claim_id!r}")

    def _argue_locked(self, claim_id):
        """Derive (verdict, evidence_count, ((child_id, verdict), ...)).

        Call with the lock held. Raises RetiredClaimError for retired
        claims.
        """
        if claim_id in self._retired:
            raise RetiredClaimError(f"claim retired: {claim_id!r}")
        ev_count = sum(1 for rec in self._bindings.values()
                       if rec.claim_id == claim_id)
        child_ids = tuple(sorted(self._children.get(claim_id, ())))
        if not child_ids:
            verdict = VERDICT_SUPPORTED if ev_count > 0 else VERDICT_OPEN
            return verdict, ev_count, ()
        pairs = tuple((cid, self._argue_locked(cid)[0]) for cid in child_ids)
        verdict = (VERDICT_SUPPORTED
                   if all(v == VERDICT_SUPPORTED for _, v in pairs)
                   else VERDICT_PARTIAL)
        return verdict, ev_count, pairs

    # -- mutations ----------------------------------------------------------

    def claim(self, claim_id, statement_digest, seq, parent_id=""):
        """Declare a safety claim; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim(seq)
            try:
                claim_id = _check_id(claim_id, "claim")
                statement_digest = _check_digest(statement_digest,
                                                 "statement_digest",
                                                 required=True)
                parent_id = _check_id(parent_id, "claim") if parent_id else ""
                if parent_id:
                    self._require_live(parent_id)
                if claim_id in self._retired:
                    raise RetiredClaimError(
                        f"claim id retired, never recycled: {claim_id!r}")
                if claim_id in self._claims:
                    raise DuplicateClaimError(
                        f"claim already declared: {claim_id!r}")
            except SafetyCaseError as e:
                self._burn(seq, e)
            rec = ClaimRecord(claim_id=claim_id, parent_id=parent_id,
                              statement_digest=statement_digest, seq=seq,
                              digest=_pin("claim", claim_id, parent_id,
                                          statement_digest, seq))
            self._claims[claim_id] = rec
            self._children.setdefault(parent_id, []).append(claim_id)
            self._last_seq = seq
            self._emit(KIND_CLAIM_DECLARED,
                       {"claim_id": claim_id, "parent_id": parent_id,
                        "digest": rec.digest}, seq)
            return rec

    def evidence(self, claim_id, evidence_id, seq, evidence_digest="",
                 kind="test"):
        """Bind one evidence item to a claim (minted ``ev-N`` id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                claim_id = _check_id(claim_id, "claim")
                evidence_id = _check_id(evidence_id, "evidence")
                evidence_digest = _check_digest(evidence_digest,
                                                "evidence_digest",
                                                required=False)
                kind = _check_evidence_kind(kind)
                self._require_live(claim_id)
                if (claim_id, evidence_id) in self._binding_keys:
                    raise DuplicateEvidenceError(
                        f"evidence already bound: {evidence_id!r} "
                        f"to {claim_id!r}")
            except SafetyCaseError as e:
                self._burn(seq, e)
            self._binding_counter += 1
            binding_id = f"ev-{self._binding_counter}"
            rec = EvidenceRecord(
                binding_id=binding_id, claim_id=claim_id,
                evidence_id=evidence_id, kind=kind,
                evidence_digest=evidence_digest, seq=seq,
                digest=_pin("evidence", binding_id, claim_id, evidence_id,
                            kind, evidence_digest, seq))
            self._bindings[binding_id] = rec
            self._binding_keys.add((claim_id, evidence_id))
            self._last_seq = seq
            # Raw evidence banned from the audit boundary: digest pin only.
            self._emit(KIND_EVIDENCE_BOUND,
                       {"binding_id": binding_id, "claim_id": claim_id,
                        "evidence_id": evidence_id, "kind": kind,
                        "digest": rec.digest}, seq)
            return rec

    def retire(self, claim_id, seq, reason="manual"):
        """Retire a claim terminally; the id is never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                claim_id = _check_id(claim_id, "claim")
                reason = _check_retire_reason(reason)
                if claim_id not in self._claims:
                    raise UnknownClaimError(f"unknown claim: {claim_id!r}")
                if claim_id in self._retired:
                    raise RetiredClaimError(
                        f"claim already retired: {claim_id!r}")
            except SafetyCaseError as e:
                self._burn(seq, e)
            rec = RetireRecord(claim_id=claim_id, reason=reason, seq=seq,
                               digest=_pin("retire", claim_id, reason, seq))
            self._retired.add(claim_id)
            self._last_seq = seq
            self._emit(KIND_RETIRED,
                       {"claim_id": claim_id, "reason": reason,
                        "digest": rec.digest}, seq)
            return rec

    # -- views ---------------------------------------------------------------

    def argue(self, claim_id, seq):
        """Pure read view: derived argument status for one claim subtree."""
        _check_seq(seq)
        with self._lock:
            if claim_id not in self._claims:
                raise UnknownClaimError(f"unknown claim: {claim_id!r}")
            verdict, ev_count, pairs = self._argue_locked(claim_id)
            child_ids = tuple(cid for cid, _ in pairs)
            child_verdicts = tuple(v for _, v in pairs)
            digest = _pin("argue", claim_id, verdict, ev_count,
                          list(child_ids), list(child_verdicts), seq)
            return ArgumentReport(claim_id=claim_id, verdict=verdict,
                                  evidence_count=ev_count,
                                  child_ids=child_ids,
                                  child_verdicts=child_verdicts, seq=seq,
                                  digest=digest)

    def claim_record(self, claim_id):
        """Return the claim record, or None when unknown (pure read)."""
        return self._claims.get(claim_id)

    def claim_ids(self):
        """Sorted declared claim ids (pure read)."""
        return tuple(sorted(self._claims))

    def children_of(self, claim_id):
        """Sorted direct child claim ids of one claim (pure read)."""
        return tuple(sorted(self._children.get(claim_id, ())))

    def retired_ids(self):
        """Sorted retired claim ids (pure read)."""
        return tuple(sorted(self._retired))

    def evidence_record(self, binding_id):
        """Return the evidence record, or None when unknown (pure read)."""
        return self._bindings.get(binding_id)

    def evidence_for(self, claim_id):
        """Sorted binding ids attached to one claim (pure read)."""
        return tuple(sorted(bid for bid, rec in self._bindings.items()
                            if rec.claim_id == claim_id))

    def stats(self):
        """Ledger population counts as data (pure read)."""
        with self._lock:
            return StatsReport(claims=len(self._claims),
                               evidence_bindings=len(self._bindings),
                               retired=len(self._retired))

    def audit_log(self):
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main():
    """Self-check: claim, decompose, bind evidence, argue, retire."""
    sc = SafetyCase()
    root_d = "sha256:" + "a" * 64
    leaf_d = "sha256:" + "b" * 64
    ev_d = "sha256:" + "c" * 64
    r = sc.claim("top", root_d, 1)
    assert r.verify("top", "", root_d)
    c1 = sc.claim("c1", leaf_d, 2, parent_id="top")
    assert c1.verify("c1", "top", leaf_d)
    c2 = sc.claim("c2", leaf_d, 3, parent_id="top")
    assert c2.verify("c2", "top", leaf_d)
    e1 = sc.evidence("c1", "test-1", 4, evidence_digest=ev_d, kind="test")
    assert e1.verify(e1.binding_id, "c1", "test-1", "test", ev_d)
    a1 = sc.argue("top", 4)
    assert a1.verdict == "partial"  # c2 still open
    assert a1.verify("top", "partial", 0, ("c1", "c2"),
                     ("supported", "open"))
    sc.evidence("c2", "eval-1", 5, evidence_digest=ev_d, kind="eval")
    a2 = sc.argue("top", 5)
    assert a2.verdict == "supported"
    rr = sc.retire("c1", 6, reason="superseded")
    assert rr.verify("c1", "superseded")
    st = sc.stats()
    assert (st.claims, st.evidence_bindings, st.retired) == (3, 2, 1)
    assert len(sc.audit_log()) == 6
    print("safety-case OK: claim, evidence, argue, retire")


if __name__ == "__main__":
    main()
