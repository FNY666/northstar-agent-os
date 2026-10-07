"""AI attribution (attribute/verify/evaluate) interface, simulated.

Research motivation: content attribution -- determining *who or what* is
responsible for an AI system's output (authorship, model identity,
training-data provenance, tool and operator responsibility) -- reduces
to one operational shape: a host declares an attribution outcome over a
pinned attribution-kind vocabulary, the ledger pins it, and a report
derives posture *from the ledger* -- the report never independently
judges whether the attribution is correct.

This module is the *AI-attribution* ledger half of that shape:

- ``AIAttribution.attribute(output_id, attribution_kind, outcome, seq,
  attribution_digest="")`` -- book one declared attribution over the
  pinned 8-kind vocabulary x the pinned 4-outcome vocabulary. The
  attributed content is pinned by ``sha256:`` digest only; raw material
  never enters a record. First attribution on an id registers the
  output.
- ``AIAttribution.verify(attribution_id, seq)`` -- **pure read**
  (seq shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the attribution holds.
- ``AIAttribution.evaluate(output_id, seq)`` -- **pure read**. Derives
  posture as data by ledger rule: ``unassessed`` (no attributions) ->
  ``contested`` (any ``inconclusive``) -> ``partially-attributed`` (any
  ``partial``) -> ``unattributed`` (any ``unattributed``) ->
  ``attributed`` (all ``attributed``), plus outcome tallies and
  ``integrity_ok`` as data.
- ``AIAttribution.retire(output_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are refused,
  reads still work.
- Pure-read views (``attribution_record`` / ``attributions_for`` /
  ``output_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_attribution_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``attributed`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw attributed content never crosses the audit boundary --
  audit rows carry ids, pinned attribution-kind/outcome labels,
  digests, and counts only.

Distinct layer: ``provenance_attestor.py`` owns provenance *claim*
issuance; ``attested_receipts.py`` owns attested-receipt bookkeeping;
``remote_attestation.py`` owns the TPM-simulated attestation *state
machine* (quotes, PCR extends, AK); ``ai_attestation.py`` owns AI-claim
attestation declarations (certification-style claims about properties).
This module owns the *content attribution* declaration lifecycle none
of them cover -- declared attributions of an output over a pinned
attribution-kind vocabulary, declared outcomes, ledger-rule posture.

Fail-closed edges (fail loudly, never guess):

- ``output_id`` / ``attribution_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``attribution_kind`` must be in the pinned 8-kind vocabulary;
  ``outcome`` must be in the pinned 4-outcome vocabulary.
- ``attribution_digest`` must be ``sha256:<64hex>`` when supplied
  (may be empty).
- ``attribute`` / ``verify`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``attr-N``).
- ``attribute`` on a retired output raises ``RetiredOutputError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* attributions reported by the host. A
  booked ``attributed`` outcome means the host declared one -- the
  module attributed nothing, measured nothing, and proves nothing about
  any real output's authorship, provenance, or responsibility.
- Digest pins prove ledger integrity and ordering, never the truth of
  any attribution or the competence of any attributing party.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if attribution state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_ATTRIBUTION_VERSION = "ai-attribution.v1"

#: Schema pin carried by records and audit events.
AI_ATTRIBUTION_SCHEMA = "northstar.ai-attribution.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ATTRIBUTED = "attributed"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ATTRIBUTED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "prompt", "completion",
     "output", "output_text", "weights", "model_output", "transcript",
     "training_data", "dataset", "data", "trace", "note", "comment",
     "authorship_evidence", "style_sample", "provenance_record",
     "attribution_text", "proof", "measurement", "benchmark_result"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned attribution-kind vocabulary (what is being attributed).
KIND_AUTHORSHIP = "authorship"
KIND_MODEL_ATTRIBUTION = "model-attribution"
KIND_TRAINING_SOURCE = "training-source"
KIND_TOOL_ATTRIBUTION = "tool-attribution"
KIND_OPERATOR_ATTRIBUTION = "operator-attribution"
KIND_DATA_ATTRIBUTION = "data-attribution"
KIND_COMPONENT_ATTRIBUTION = "component-attribution"
KIND_LICENSE_ATTRIBUTION = "license-attribution"
ATTRIBUTION_KINDS = (
    KIND_AUTHORSHIP,
    KIND_MODEL_ATTRIBUTION,
    KIND_TRAINING_SOURCE,
    KIND_TOOL_ATTRIBUTION,
    KIND_OPERATOR_ATTRIBUTION,
    KIND_DATA_ATTRIBUTION,
    KIND_COMPONENT_ATTRIBUTION,
    KIND_LICENSE_ATTRIBUTION,
)

#: Pinned attribution-outcome vocabulary. Outcomes are host-reported data.
OUTCOME_ATTRIBUTED = "attributed"
OUTCOME_PARTIAL = "partial"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_UNATTRIBUTED = "unattributed"
OUTCOMES = (
    OUTCOME_ATTRIBUTED,
    OUTCOME_PARTIAL,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_UNATTRIBUTED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNASSESSED = "unassessed"
POSTURE_CONTESTED = "contested"
POSTURE_PARTIALLY_ATTRIBUTED = "partially-attributed"
POSTURE_UNATTRIBUTED = "unattributed"
POSTURE_ATTRIBUTED = "attributed"
POSTURES = (
    POSTURE_UNASSESSED,
    POSTURE_CONTESTED,
    POSTURE_PARTIALLY_ATTRIBUTED,
    POSTURE_UNATTRIBUTED,
    POSTURE_ATTRIBUTED,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SCOPE_CHANGE = "scope-change"
REASON_ATTRIBUTION_LOSS = "attribution-loss"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_SCOPE_CHANGE,
    REASON_ATTRIBUTION_LOSS,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIAttributionError(Exception):
    """Base error for the AI-attribution ledger (programming errors)."""


class BadIdError(AIAttributionError):
    """Raised when an output/attribution id is malformed."""


class DuplicateAttributionError(AIAttributionError):
    """Raised when a minted attribution id somehow collides (never)."""


class UnknownOutputError(AIAttributionError):
    """Raised when an output id names no attributed output."""


class UnknownAttributionError(AIAttributionError):
    """Raised when an attribution id names no booked attribution."""


class RetiredOutputError(AIAttributionError):
    """Raised when mutating a retired output."""


class DoubleRetireError(AIAttributionError):
    """Raised when retiring an already-retired output."""


class BadAttributionKindError(AIAttributionError):
    """Raised when an attribution kind is not in the pinned vocabulary."""


class BadOutcomeError(AIAttributionError):
    """Raised when an outcome is not in the pinned vocabulary."""


class BadDigestError(AIAttributionError):
    """Raised when an attribution digest is not a sha256: pin."""


class BadReasonError(AIAttributionError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIAttributionError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIAttributionError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


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


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AI_ATTRIBUTION_SCHEMA,
        "parts": list(parts),
    })


def ai_attribution_audit_event(kind: str, detail: Dict[str, object],
                               seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-attribution ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_ATTRIBUTION_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class AttributionRecord:
    """Frozen record of one declared attribution (digest-pinned)."""
    attribution_id: str
    output_id: str
    attribution_kind: str
    outcome: str
    attribution_digest: str
    seq: int
    digest: str

    def verify(self, attribution_id: str, output_id: str,
               attribution_kind: str, outcome: str,
               attribution_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "attribution", attribution_id, output_id, attribution_kind,
            outcome, attribution_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    attribution_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, attribution_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", attribution_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    output_id: str
    posture: str
    n_attributions: int
    n_attributed: int
    n_partial: int
    n_inconclusive: int
    n_unattributed: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, output_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", output_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    output_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, output_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", output_id, reason, self.seq)


class AIAttribution:
    """AI-attribution ledger (declared attributions, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._attributions: Dict[str, AttributionRecord] = {}
        self._by_output: Dict[str, Tuple[str, ...]] = {}
        self._attribution_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, output_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if output_id:
            detail["output_id"] = output_id
        event = ai_attribution_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_attribution_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def attribute(self, output_id: str, attribution_kind: str, outcome: str,
                  seq: int, attribution_digest: str = "") -> AttributionRecord:
        """Book one declared attribution. First attribution on an id
        registers the output. Pins the attribution digest, never the
        attributed content. Returns the frozen ``AttributionRecord``
        (minted ``attr-N``)."""
        self._claim(seq)
        try:
            output_id = _check_id(output_id, "output_id")
            if isinstance(attribution_kind, bool) or not isinstance(
                    attribution_kind, str):
                raise BadAttributionKindError(
                    f"attribution_kind must be str, got "
                    f"{type(attribution_kind).__name__}")
            if attribution_kind not in ATTRIBUTION_KINDS:
                raise BadAttributionKindError(
                    f"attribution_kind must be one of "
                    f"{sorted(ATTRIBUTION_KINDS)}, got {attribution_kind!r}")
            if isinstance(outcome, bool) or not isinstance(outcome, str):
                raise BadOutcomeError(
                    f"outcome must be str, got {type(outcome).__name__}")
            if outcome not in OUTCOMES:
                raise BadOutcomeError(
                    f"outcome must be one of {sorted(OUTCOMES)}, "
                    f"got {outcome!r}")
            attribution_digest = _check_digest(
                attribution_digest, "attribution_digest", allow_empty=True)
            with self._lock:
                if output_id in self._retired:
                    raise RetiredOutputError(
                        f"output is retired: {output_id!r}")
                attribution_id = f"attr-{len(self._attribution_ids) + 1}"
                if attribution_id in self._attributions:
                    raise DuplicateAttributionError(
                        f"attribution id collision: {attribution_id!r}")
                record = AttributionRecord(
                    attribution_id=attribution_id,
                    output_id=output_id,
                    attribution_kind=attribution_kind,
                    outcome=outcome,
                    attribution_digest=attribution_digest,
                    seq=seq,
                    digest=_pin("attribution", attribution_id, output_id,
                                attribution_kind, outcome, attribution_digest,
                                seq),
                )
                self._attributions[attribution_id] = record
                self._attribution_ids = (
                    self._attribution_ids + (attribution_id,))
                self._by_output[output_id] = (
                    self._by_output.get(output_id, ()) + (attribution_id,))
        except AIAttributionError:
            self._burn(seq, output_id if isinstance(output_id, str) else "")
            raise
        self._emit(KIND_ATTRIBUTED,
                   {"output_id": output_id,
                    "attribution_id": record.attribution_id,
                    "attribution_kind": attribution_kind,
                    "outcome": outcome,
                    "attribution_digest": attribution_digest}, seq)
        return record

    def verify(self, attribution_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive an attribution's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        attribution_id = _check_id(attribution_id, "attribution_id")
        with self._lock:
            if attribution_id not in self._attributions:
                raise UnknownAttributionError(
                    f"unknown attribution: {attribution_id!r}")
            rec = self._attributions[attribution_id]
            intact = rec.verify(
                rec.attribution_id, rec.output_id, rec.attribution_kind,
                rec.outcome, rec.attribution_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                attribution_id=attribution_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", attribution_id, verdict, seq),
            )

    def evaluate(self, output_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``inconclusive`` -> ``contested``; any ``unattributed`` ->
        ``unattributed``; any ``partial`` -> ``partially-attributed``;
        all ``attributed`` -> ``attributed``). Validates seq shape,
        consumes nothing, writes no audit row. Returns the frozen
        ``EvaluationReport``."""
        _check_seq(seq)
        output_id = _check_id(output_id, "output_id")
        with self._lock:
            if output_id not in self._by_output:
                raise UnknownOutputError(
                    f"unknown output: {output_id!r}")
            ids = self._by_output[output_id]
            recs = [self._attributions[i] for i in ids]
            n_attributed = sum(1 for r in recs
                               if r.outcome == OUTCOME_ATTRIBUTED)
            n_partial = sum(1 for r in recs
                            if r.outcome == OUTCOME_PARTIAL)
            n_inconclusive = sum(
                1 for r in recs if r.outcome == OUTCOME_INCONCLUSIVE)
            n_unattributed = sum(
                1 for r in recs if r.outcome == OUTCOME_UNATTRIBUTED)
            integrity_ok = all(
                r.verify(r.attribution_id, r.output_id, r.attribution_kind,
                         r.outcome, r.attribution_digest) for r in recs)
            if n_inconclusive:
                posture = POSTURE_CONTESTED
            elif n_unattributed:
                posture = POSTURE_UNATTRIBUTED
            elif n_partial:
                posture = POSTURE_PARTIALLY_ATTRIBUTED
            else:
                posture = POSTURE_ATTRIBUTED
            return EvaluationReport(
                output_id=output_id,
                posture=posture,
                n_attributions=len(recs),
                n_attributed=n_attributed,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_unattributed=n_unattributed,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", output_id, posture, seq),
            )

    def retire(self, output_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire an output. Ids are never recycled; post-retire
        mutations are refused, reads still work. Returns the frozen
        ``RetireRecord``."""
        self._claim(seq)
        try:
            output_id = _check_id(output_id, "output_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if output_id in self._retired:
                    raise DoubleRetireError(
                        f"output already retired: {output_id!r}")
                record = RetireRecord(
                    output_id=output_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", output_id, reason, seq),
                )
                self._retired[output_id] = record
        except AIAttributionError:
            self._burn(seq, output_id if isinstance(output_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"output_id": output_id, "reason": reason}, seq)
        return record

    def attribution_record(self, attribution_id: str,
                           seq: int) -> AttributionRecord:
        """Pure read view of one booked attribution."""
        _check_seq(seq)
        attribution_id = _check_id(attribution_id, "attribution_id")
        with self._lock:
            if attribution_id not in self._attributions:
                raise UnknownAttributionError(
                    f"unknown attribution: {attribution_id!r}")
            return self._attributions[attribution_id]

    def attributions_for(self, output_id: str,
                         seq: int) -> Tuple[str, ...]:
        """Pure read view of attribution ids for one output, in book order."""
        _check_seq(seq)
        output_id = _check_id(output_id, "output_id")
        with self._lock:
            if output_id not in self._by_output:
                raise UnknownOutputError(
                    f"unknown output: {output_id!r}")
            return self._by_output[output_id]

    def output_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered output ids, in first-attribute order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_output.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired output ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "outputs": len(self._by_output),
                "attributions": len(self._attributions),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: attribute, verify, evaluate, retire, pins, audit."""
    aa = AIAttribution()
    assert AI_ATTRIBUTION_VERSION == "ai-attribution.v1"
    assert AI_ATTRIBUTION_SCHEMA == "northstar.ai-attribution.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = aa.attribute("out-1", KIND_AUTHORSHIP, OUTCOME_ATTRIBUTED, 1,
                       digest)
    assert rec.attribution_id == "attr-1"
    assert rec.verify("attr-1", "out-1", KIND_AUTHORSHIP,
                      OUTCOME_ATTRIBUTED, digest)
    assert not rec.verify("attr-1", "out-1", KIND_AUTHORSHIP,
                          OUTCOME_UNATTRIBUTED, digest)
    vr = aa.verify("attr-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("attr-1", "verified")
    ev = aa.evaluate("out-1", 3)
    assert ev.posture == POSTURE_ATTRIBUTED
    assert ev.integrity_ok
    assert ev.verify("out-1", POSTURE_ATTRIBUTED)
    aa.attribute("out-1", KIND_DATA_ATTRIBUTION, OUTCOME_UNATTRIBUTED, 4,
                 digest)
    ev = aa.evaluate("out-1", 5)
    assert ev.posture == POSTURE_UNATTRIBUTED
    assert ev.n_attributions == 2 and ev.n_unattributed == 1
    aa.attribute("out-1", KIND_TOOL_ATTRIBUTION, OUTCOME_INCONCLUSIVE, 6,
                 digest)
    ev = aa.evaluate("out-1", 7)
    assert ev.posture == POSTURE_CONTESTED
    rr = aa.retire("out-1", 8)
    assert rr.verify("out-1", REASON_MANUAL)
    try:
        aa.attribute("out-1", KIND_OPERATOR_ATTRIBUTION,
                     OUTCOME_ATTRIBUTED, 9)
    except RetiredOutputError:
        pass
    else:
        raise AssertionError("attribute on retired output must fail closed")
    assert aa.stats()["outputs"] == 1
    kinds = [row["kind"] for row in aa.audit_log()]
    assert kinds == [KIND_ATTRIBUTED, KIND_ATTRIBUTED, KIND_ATTRIBUTED,
                     KIND_RETIRED, KIND_REJECTED]
    print("ai-attribution OK: attribute, verify, evaluate, retire, pins, "
          "audit")


if __name__ == "__main__":
    main()
