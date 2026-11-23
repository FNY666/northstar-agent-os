"""System card: model system-documentation decision ledger, Simulated.

Research note: a *system card* (as pioneered by Anthropic for its Claude
releases) is the published technical document accompanying a model
release - it describes the model's capabilities and evaluations, the
alignment and safety work done before deployment, the usage policies and
mitigations in force, and the deployment details. Regulators, partners,
and the public then judge the release against that card. What matters
here is the *decision ledger*: which cards were declared for which
models, which declared assessment outcomes were booked under each card,
and which cards were declared published and through which channel -
defensible bookkeeping, not proof of real evaluations or real
publications.

This module owns the create -> assess -> publish lifecycle:

* **create()** - declare one system card for a model version; the model
  and its artifacts travel as ``sha256:`` digest pins only, raw
  capabilities text, weights, and datasets never enter records.
  Duplicate card ids are refused; retired ids are never recycled.
* **assess()** - book one declared assessment outcome (minted ``asm-N``
  ids) under a pinned dimension vocabulary (capability, red-team,
  alignment, safety, security, benchmark); outcomes are booked as
  *data*, never proof that an evaluation was actually run.
* **publish()** - terminal declared publication (minted ``pub-N`` ids)
  over pinned channels (internal / external / regulatory); requires at
  least one booked assessment; published card ids are retired forever.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``system-card.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module evaluates nothing, red-teams nothing, and
publishes nothing. A booked ``pass`` means "the host declared a passing
outcome", never "the model passed a real evaluation"; a booked
``published`` means "the host declared publication", never "a document
was actually released". Raw model names, weights, capability text, and
evaluation data never enter records or cross the audit boundary -
digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
SYSTEM_CARD_VERSION = "system-card.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.system-card.v1"

#: Pinned assessment-dimension vocabulary (system-card evaluation areas).
DIMENSIONS = (
    "capability-evaluation",
    "red-teaming",
    "alignment-evaluation",
    "safety-evaluation",
    "security-evaluation",
    "benchmark",
)

#: Pinned assessment-outcome vocabulary, booked as data, never proof.
OUTCOMES = (
    "pass",
    "fail",
    "conditional",
    "not-assessed",
)

#: Pinned publication-channel vocabulary.
CHANNELS = (
    "internal",
    "external",
    "regulatory",
)

#: Pinned publication-visibility vocabulary.
VISIBILITIES = (
    "internal",
    "partner",
    "public",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "created",
    "assessed",
    "published",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "model",
        "model_name",
        "model_id",
        "weights",
        "parameters",
        "params",
        "dataset",
        "training_data",
        "text",
        "content",
        "note",
        "notes",
        "description",
        "detail",
        "details",
        "prompt",
        "prompts",
        "secret",
        "key",
        "raw",
        "payload",
        "capability",
        "score",
        "evaluation",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SystemCardError(Exception):
    """Base error for system-card ledger misuse."""


class BadIdError(SystemCardError):
    """Malformed card, assessment, or publication id."""


class DuplicateCardError(SystemCardError):
    """System card already declared."""


class UnknownCardError(SystemCardError):
    """System card not declared."""


class RetiredCardError(SystemCardError):
    """System card id already published/retired; never recycled."""


class BadDigestError(SystemCardError):
    """Malformed sha256: digest pin."""


class BadVersionError(SystemCardError):
    """Malformed card version label."""


class BadDimensionError(SystemCardError):
    """Unknown assessment dimension."""


class BadOutcomeError(SystemCardError):
    """Unknown assessment outcome."""


class BadChannelError(SystemCardError):
    """Unknown publication channel."""


class BadVisibilityError(SystemCardError):
    """Unknown publication visibility."""


class NoAssessmentError(SystemCardError):
    """Card has no booked assessments; may not be published."""


class AlreadyPublishedError(SystemCardError):
    """Card already published."""


class SeqOrderError(SystemCardError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(SystemCardError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_version(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise BadVersionError("version must be a non-empty str <= 64 chars")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CardRecord:
    card_id: str
    model_digest: str
    version: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "card_id": self.card_id,
            "model_digest": self.model_digest,
            "version": self.version,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "card_id": self.card_id,
                "model_digest": self.model_digest,
                "version": self.version,
            }
        )


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    card_id: str
    dimension: str
    outcome: str
    detail_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "card_id": self.card_id,
            "dimension": self.dimension,
            "outcome": self.outcome,
            "detail_digest": self.detail_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "card_id": self.card_id,
                "dimension": self.dimension,
                "outcome": self.outcome,
                "detail_digest": self.detail_digest,
            }
        )


@dataclass(frozen=True)
class PublicationRecord:
    publication_id: str
    card_id: str
    channel: str
    visibility: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "publication_id": self.publication_id,
            "card_id": self.card_id,
            "channel": self.channel,
            "visibility": self.visibility,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "publication_id": self.publication_id,
                "card_id": self.card_id,
                "channel": self.channel,
                "visibility": self.visibility,
            }
        )


@dataclass(frozen=True)
class StatusReport:
    n_cards: int
    n_assessments: int
    n_published: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_cards": self.n_cards,
            "n_assessments": self.n_assessments,
            "n_published": self.n_published,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_cards": self.n_cards,
                "n_assessments": self.n_assessments,
                "n_published": self.n_published,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def system_card_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the system-card ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class SystemCard:
    """System-card decision ledger, Simulated.

    ``create()`` / ``assess()`` / ``publish()`` mutate the ledger and
    consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cards: Dict[str, CardRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_for_card: Dict[str, List[str]] = {}
        self._publications: Dict[str, PublicationRecord] = {}
        self._retired: set = set()
        self._asm_counter = 0
        self._pub_counter = 0
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _require_read_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = system_card_audit_event("rejected", seq,
                                          rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(system_card_audit_event(audit_kind, seq, **details))

    # -- create ------------------------------------------------------------

    def create(
        self,
        card_id: str,
        seq: int,
        model_digest: str = "",
        version: str = "",
    ) -> CardRecord:
        """Declare one system card for a model version.

        The model and its artifacts travel as a ``sha256:`` digest pin
        only - raw names, weights, and datasets never enter records.
        """
        with self._lock:
            try:
                self._claim(seq)
            except SystemCardError:
                raise
            try:
                _require_id(card_id, "card_id")
                if card_id in self._retired:
                    raise RetiredCardError(
                        f"card id already published/retired: {card_id!r}")
                if model_digest:
                    _require_digest(model_digest, "model_digest")
                else:
                    model_digest = "sha256:" + "00" * 32
                if version:
                    _require_version(version)
                else:
                    version = "unspecified"
                if card_id in self._cards:
                    raise DuplicateCardError(
                        f"card already declared: {card_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "card_id": card_id,
                     "model_digest": model_digest, "version": version}
                )
                record = CardRecord(
                    card_id=card_id, model_digest=model_digest,
                    version=version, digest=digest,
                )
                self._cards[card_id] = record
                self._emit(
                    "created", seq, card_id=card_id, version=version,
                )
                return record
            except SystemCardError:
                self._burn(seq, "create")
                raise

    # -- assess ------------------------------------------------------------

    def assess(
        self,
        card_id: str,
        seq: int,
        dimension: str = "capability-evaluation",
        outcome: str = "pass",
        detail_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared assessment outcome (minted ``asm-N``).

        Outcomes are booked as *data*, never proof that an evaluation
        was actually run.
        """
        with self._lock:
            try:
                self._claim(seq)
            except SystemCardError:
                raise
            try:
                _require_id(card_id, "card_id")
                if card_id in self._retired:
                    raise RetiredCardError(
                        f"card already published: {card_id!r}")
                if card_id not in self._cards:
                    raise UnknownCardError(
                        f"unknown card: {card_id!r}")
                if dimension not in DIMENSIONS:
                    raise BadDimensionError(
                        f"dimension must be one of {DIMENSIONS}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {OUTCOMES}")
                if detail_digest:
                    _require_digest(detail_digest, "detail_digest")
                else:
                    detail_digest = "sha256:" + "00" * 32
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "assessment_id": asm_id,
                     "card_id": card_id, "dimension": dimension,
                     "outcome": outcome, "detail_digest": detail_digest}
                )
                record = AssessmentRecord(
                    assessment_id=asm_id, card_id=card_id,
                    dimension=dimension, outcome=outcome,
                    detail_digest=detail_digest, digest=digest,
                )
                self._assessments[asm_id] = record
                self._assessments_for_card.setdefault(card_id, []).append(asm_id)
                self._emit(
                    "assessed", seq, assessment_id=asm_id, card_id=card_id,
                    dimension=dimension, outcome=outcome,
                )
                return record
            except SystemCardError:
                self._burn(seq, "assess")
                raise

    # -- publish -----------------------------------------------------------

    def publish(
        self,
        card_id: str,
        seq: int,
        channel: str = "internal",
        visibility: str = "internal",
    ) -> PublicationRecord:
        """Declare one system-card publication (minted ``pub-N``).

        Terminal: requires at least one booked assessment, and the card
        id is retired forever - later mutations on it fail closed.
        """
        with self._lock:
            try:
                self._claim(seq)
            except SystemCardError:
                raise
            try:
                _require_id(card_id, "card_id")
                if card_id in self._retired:
                    raise RetiredCardError(
                        f"card already published: {card_id!r}")
                if card_id not in self._cards:
                    raise UnknownCardError(
                        f"unknown card: {card_id!r}")
                if channel not in CHANNELS:
                    raise BadChannelError(
                        f"channel must be one of {CHANNELS}")
                if visibility not in VISIBILITIES:
                    raise BadVisibilityError(
                        f"visibility must be one of {VISIBILITIES}")
                if not self._assessments_for_card.get(card_id):
                    raise NoAssessmentError(
                        f"card has no booked assessments: {card_id!r}")
                self._pub_counter += 1
                pub_id = f"pub-{self._pub_counter}"
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "publication_id": pub_id,
                     "card_id": card_id, "channel": channel,
                     "visibility": visibility}
                )
                record = PublicationRecord(
                    publication_id=pub_id, card_id=card_id,
                    channel=channel, visibility=visibility, digest=digest,
                )
                self._publications[card_id] = record
                self._retired.add(card_id)
                self._emit(
                    "published", seq, publication_id=pub_id, card_id=card_id,
                    channel=channel, visibility=visibility,
                )
                return record
            except SystemCardError:
                self._burn(seq, "publish")
                raise

    # -- pure-read views ---------------------------------------------------

    def card_record(self, seq: int, card_id: str) -> CardRecord:
        """Return one card record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(card_id, "card_id")
            if card_id not in self._cards:
                raise UnknownCardError(f"unknown card: {card_id!r}")
            return self._cards[card_id]

    def assessment_record(
        self, seq: int, assessment_id: str
    ) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(assessment_id, "assessment_id")
            if assessment_id not in self._assessments:
                raise UnknownCardError(
                    f"unknown assessment: {assessment_id!r}")
            return self._assessments[assessment_id]

    def assessments_for(self, seq: int, card_id: str) -> Tuple[str, ...]:
        """Assessment ids booked under one card, in mint order."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(card_id, "card_id")
            if card_id not in self._cards:
                raise UnknownCardError(f"unknown card: {card_id!r}")
            return tuple(self._assessments_for_card.get(card_id, ()))

    def publication_record(self, seq: int, card_id: str) -> PublicationRecord:
        """Return one card's publication record (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            _require_id(card_id, "card_id")
            if card_id not in self._publications:
                raise UnknownCardError(
                    f"card not published: {card_id!r}")
            return self._publications[card_id]

    def card_ids(self, seq: int) -> Tuple[str, ...]:
        """All declared card ids, in declaration order."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._cards.keys())

    def published_ids(self, seq: int) -> Tuple[str, ...]:
        """All published card ids, in publication order."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._publications.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired card ids (published ids are terminal)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            rejected = sum(
                1 for row in self._audit if row["kind"] == "rejected"
            )
            return {
                "cards": len(self._cards),
                "assessments": len(self._assessments),
                "publications": len(self._publications),
                "retired": len(self._retired),
                "rejected": rejected,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)

    def status(self, seq: int) -> StatusReport:
        """Ledger-wide status snapshot (pure read)."""
        with self._lock:
            self._require_read_seq(seq)
            n_cards = len(self._cards)
            n_assessments = len(self._assessments)
            n_published = len(self._publications)
            integrity_ok = all(
                rec.verify() for rec in self._cards.values()
            ) and all(
                rec.verify() for rec in self._assessments.values()
            ) and all(
                rec.verify() for rec in self._publications.values()
            )
            digest = _digest_pin(
                {"schema": SCHEMA_PIN, "n_cards": n_cards,
                 "n_assessments": n_assessments,
                 "n_published": n_published, "integrity_ok": integrity_ok}
            )
            return StatusReport(
                n_cards=n_cards, n_assessments=n_assessments,
                n_published=n_published, integrity_ok=integrity_ok,
                digest=digest,
            )


def main() -> None:
    """System-card self-check: create, assess, publish, pins, audit."""
    ledger = SystemCard()
    ledger.create("card-1", 1, version="v1")
    ledger.assess("card-1", 2, dimension="red-teaming", outcome="pass")
    ledger.publish("card-1", 3, channel="external", visibility="public")
    report = ledger.status(3)
    assert report.verify()
    assert report.n_cards == 1
    assert report.n_assessments == 1
    assert report.n_published == 1
    print("system-card OK: create, assess, publish, pins, audit")


if __name__ == "__main__":
    main()
