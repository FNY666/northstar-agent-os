"""Model Card: transparency-reporting decision ledger (Mitchell et al. 2019), Simulated.

Research note: Mitchell et al., "Model Cards for Model Reporting"
(2019) proposed short documents accompanying trained ML models that
report intended use, training/evaluation data, performance metrics
across conditions, and known limitations - structured transparency so
deployers, auditors, and affected people can reason about fitness for
purpose. What matters here is the *decision ledger*: which model cards
were declared, what fields were booked against them, and which cards
were declared published - defensible bookkeeping, not proof of
transparency or of any model property.

This module owns the create -> publish -> verify lifecycle:

* **create()** - book one declared model card (pinned intended-use
  vocabulary, pinned limitation vocabulary, host-declared metrics as
  data, digest pins for model/training/evaluation artifacts); raw
  descriptions, names, and free text never enter records - digest pins
  only. Duplicates refused fail-closed.
* **publish()** - terminal: book the declared publication of one card
  (minted ``pub-N`` ids). One publication per card; published ids are
  never recycled.
* **verify()** - pure read: re-derive every digest pin and report
  ``published`` / ``integrity_ok`` as data, never raised.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``model-card.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module trains no model, evaluates nothing, audits no
documentation, and publishes nothing to the world. A booked card means
"the host declared these fields"; a booked ``published`` means "the
host declared the card published". Model weights, datasets, and free
text never enter records or cross the audit boundary - digest pins only.
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
MODEL_CARD_VERSION = "model-card.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.model-card.v1"

#: Pinned intended-use vocabulary (Mitchell et al. "intended use").
INTENDED_USES = (
    "classification",
    "generation",
    "recommendation",
    "detection",
    "decision-support",
    "research",
)

#: Pinned limitation vocabulary (Mitchell et al. "caveats and
#: recommendations", booked as data).
LIMITATIONS = (
    "data-bias",
    "domain-shift",
    "language-limits",
    "adversarial-vulnerability",
    "compute-cost",
    "privacy-risk",
    "label-noise",
    "out-of-scope-use",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "created",
    "published",
    "rejected",
)

#: Zero pin used when an artifact digest was not supplied.
_ZERO_PIN = "sha256:" + "00" * 32

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "description",
        "text",
        "content",
        "details",
        "detail",
        "notes",
        "note",
        "payload",
        "raw",
        "data",
        "name",
        "model_name",
        "author",
        "owner",
        "owner_name",
        "team",
        "contact",
        "email",
        "documentation",
        "doc",
        "summary",
        "rationale",
        "secret",
        "key",
        "weights",
        "dataset",
        "samples",
    }
)

#: Upper bound for exact-integer metric values (2**53).
_INT_BOUND = 2**53


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ModelCardError(Exception):
    """Base error for model-card ledger misuse."""


class BadIdError(ModelCardError):
    """Malformed card, model, or publication id."""


class DuplicateCardError(ModelCardError):
    """Card id already booked."""


class UnknownCardError(ModelCardError):
    """Card id not booked."""


class RetiredCardError(ModelCardError):
    """Card id retired; never recycled."""


class AlreadyPublishedError(ModelCardError):
    """Card already published; one publication per card."""


class BadUseError(ModelCardError):
    """Unknown intended use."""


class BadLimitationError(ModelCardError):
    """Unknown or malformed limitation."""


class BadMetricError(ModelCardError):
    """Malformed metric name or value."""


class BadDigestError(ModelCardError):
    """Malformed sha256: digest pin."""


class BadLabelError(ModelCardError):
    """Malformed version label."""


class SeqOrderError(ModelCardError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ModelCardError):
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


def _optional_digest(pin: str, field_name: str) -> str:
    if not pin:
        return _ZERO_PIN
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


def _check_metrics(metrics: Any) -> Tuple[Tuple[str, Any], ...]:
    """Validate host-declared metrics; return sorted (name, value) pairs."""
    if not isinstance(metrics, (tuple, list)):
        raise BadMetricError("metrics must be a tuple/list of (name, value) pairs")
    pairs: List[Tuple[str, Any]] = []
    seen = set()
    for item in metrics:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise BadMetricError("each metric must be a (name, value) pair")
        name, value = item
        if not isinstance(name, str) or not name or len(name) > 64:
            raise BadMetricError("metric name must be a non-empty str <= 64 chars")
        if name in seen:
            raise BadMetricError(f"duplicate metric name: {name!r}")
        seen.add(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadMetricError(f"metric value must be a number: {name!r}")
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise BadMetricError(f"metric value must be finite: {name!r}")
        else:
            if abs(value) > _INT_BOUND:
                raise BadMetricError(f"metric int out of exact range: {name!r}")
        pairs.append((name, value))
    return tuple(sorted(pairs, key=lambda p: p[0]))


def _check_limitations(limitations: Any) -> Tuple[str, ...]:
    if not isinstance(limitations, (tuple, list)):
        raise BadLimitationError("limitations must be a tuple/list")
    out: List[str] = []
    for item in limitations:
        if item not in LIMITATIONS:
            raise BadLimitationError(
                f"limitation must be one of {LIMITATIONS}"
            )
        if item in out:
            raise BadLimitationError(f"duplicate limitation: {item!r}")
        out.append(item)
    return tuple(out)


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CardRecord:
    card_id: str
    model_id: str
    intended_use: str
    limitations: Tuple[str, ...]
    metrics: Tuple[Tuple[str, Any], ...]
    model_digest: str
    training_digest: str
    eval_digest: str
    version_label: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "card_id": self.card_id,
            "model_id": self.model_id,
            "intended_use": self.intended_use,
            "limitations": list(self.limitations),
            "metrics": [
                {"name": name, "value": value} for name, value in self.metrics
            ],
            "model_digest": self.model_digest,
            "training_digest": self.training_digest,
            "eval_digest": self.eval_digest,
            "version_label": self.version_label,
            "digest": self.digest,
        }

    def _pin_payload(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "card_id": self.card_id,
            "model_id": self.model_id,
            "intended_use": self.intended_use,
            "limitations": list(self.limitations),
            "metrics": [
                {"name": name, "value": value} for name, value in self.metrics
            ],
            "model_digest": self.model_digest,
            "training_digest": self.training_digest,
            "eval_digest": self.eval_digest,
            "version_label": self.version_label,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(self._pin_payload())


@dataclass(frozen=True)
class PublicationRecord:
    publication_id: str
    card_id: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "publication_id": self.publication_id,
            "card_id": self.card_id,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "publication_id": self.publication_id,
                "card_id": self.card_id,
            }
        )


@dataclass(frozen=True)
class VerifyReport:
    card_id: str
    published: bool
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "card_id": self.card_id,
            "published": self.published,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "card_id": self.card_id,
                "published": self.published,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def model_card_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the model-card ledger."""
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


class ModelCard:
    """Model-card transparency decision ledger, Simulated.

    ``create()`` / ``publish()`` mutate the ledger and consume caller seqs;
    ``verify()`` and the other views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cards: Dict[str, CardRecord] = {}
        self._publications: Dict[str, PublicationRecord] = {}
        self._published_cards: Dict[str, str] = {}
        self._retired: set = set()
        self._pub_seq = 0
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

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = model_card_audit_event("rejected", seq,
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
        self._audit.append(model_card_audit_event(audit_kind, seq, **details))

    # -- create ------------------------------------------------------------

    def create(
        self,
        card_id: str,
        seq: int,
        model_id: str = "",
        intended_use: str = "classification",
        limitations: Tuple[str, ...] = (),
        metrics: Tuple[Tuple[str, Any], ...] = (),
        model_digest: str = "",
        training_digest: str = "",
        eval_digest: str = "",
        version_label: str = "1.0.0",
    ) -> CardRecord:
        """Book one declared model card.

        Intended use and limitations come from pinned vocabularies;
        metrics are host-declared (name, value) pairs booked as data;
        model/training/evaluation artifacts travel as ``sha256:`` digest
        pins only - raw weights, data descriptions, and free text never
        enter records. Duplicate ids refused fail-closed.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ModelCardError:
                raise
            try:
                cid = _require_id(card_id, "card_id")
                mid = _require_id(model_id, "model_id")
                if cid in self._retired:
                    raise RetiredCardError(
                        f"card id retired, never recycled: {cid!r}"
                    )
                if cid in self._cards:
                    raise DuplicateCardError(
                        f"card already booked: {cid!r}"
                    )
                if intended_use not in INTENDED_USES:
                    raise BadUseError(
                        f"intended_use must be one of {INTENDED_USES}"
                    )
                lims = _check_limitations(limitations)
                mets = _check_metrics(metrics)
                if (not isinstance(version_label, str) or not version_label
                        or len(version_label) > 32):
                    raise BadLabelError(
                        "version_label must be a non-empty str <= 32 chars"
                    )
                mp = _optional_digest(model_digest, "model_digest")
                tp = _optional_digest(training_digest, "training_digest")
                ep = _optional_digest(eval_digest, "eval_digest")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "card_id": cid,
                        "model_id": mid,
                        "intended_use": intended_use,
                        "limitations": list(lims),
                        "metrics": [
                            {"name": name, "value": value}
                            for name, value in mets
                        ],
                        "model_digest": mp,
                        "training_digest": tp,
                        "eval_digest": ep,
                        "version_label": version_label,
                    }
                )
                record = CardRecord(
                    card_id=cid,
                    model_id=mid,
                    intended_use=intended_use,
                    limitations=lims,
                    metrics=mets,
                    model_digest=mp,
                    training_digest=tp,
                    eval_digest=ep,
                    version_label=version_label,
                    digest=digest,
                )
                self._cards[cid] = record
                self._emit(
                    "created", seq, card_id=cid, model_id=mid,
                    intended_use=intended_use, version_label=version_label,
                )
                return record
            except ModelCardError:
                self._burn(seq, "create")
                raise

    # -- publish -----------------------------------------------------------

    def publish(self, card_id: str, seq: int) -> PublicationRecord:
        """Terminal: book the declared publication of one card.

        The publication id is minted (``pub-N``); one publication per
        card. Books the *declaration*, never proof the card was seen.
        """
        with self._lock:
            try:
                self._claim(seq)
            except ModelCardError:
                raise
            try:
                cid = _require_id(card_id, "card_id")
                if cid not in self._cards:
                    raise UnknownCardError(f"unknown card: {cid!r}")
                if cid in self._published_cards:
                    raise AlreadyPublishedError(
                        f"card already published: {cid!r}"
                    )
                self._pub_seq += 1
                pub_id = f"pub-{self._pub_seq}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "publication_id": pub_id,
                        "card_id": cid,
                    }
                )
                record = PublicationRecord(
                    publication_id=pub_id, card_id=cid, digest=digest
                )
                self._publications[pub_id] = record
                self._published_cards[cid] = pub_id
                self._emit("published", seq, publication_id=pub_id,
                           card_id=cid)
                return record
            except ModelCardError:
                self._burn(seq, "publish")
                raise

    # -- verify ------------------------------------------------------------

    def verify(self, card_id: str, seq: int) -> VerifyReport:
        """Pure read: digest-pin integrity and publication state as data.

        Tamper is reported as ``integrity_ok=False`` data, never raised.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("read seq must be a non-negative int")
            cid = _require_id(card_id, "card_id")
            record = self._cards.get(cid)
            if record is None:
                raise UnknownCardError(f"unknown card: {cid!r}")
            integrity_ok = record.verify()
            pub_id = self._published_cards.get(cid)
            if pub_id is not None:
                pub_record = self._publications[pub_id]
                integrity_ok = integrity_ok and pub_record.verify()
            published = pub_id is not None
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "card_id": cid,
                    "published": published,
                    "integrity_ok": integrity_ok,
                }
            )
            return VerifyReport(
                card_id=cid, published=published, integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads) -------------------------------------------------

    def card_record(self, seq: int, card_id: str) -> CardRecord:
        """Pure read: one card record."""
        with self._lock:
            self._require_read_seq(seq)
            cid = _require_id(card_id, "card_id")
            record = self._cards.get(cid)
            if record is None:
                raise UnknownCardError(f"unknown card: {cid!r}")
            return record

    def publication_record(self, seq: int, publication_id: str) -> PublicationRecord:
        """Pure read: one publication record."""
        with self._lock:
            self._require_read_seq(seq)
            pid = _require_id(publication_id, "publication_id")
            record = self._publications.get(pid)
            if record is None:
                raise UnknownCardError(f"unknown publication: {pid!r}")
            return record

    def card_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: booked card ids, sorted."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._cards))

    def publication_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: minted publication ids, sorted."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._publications))

    def is_published(self, seq: int, card_id: str) -> bool:
        """Pure read: whether a card has a booked publication."""
        with self._lock:
            self._require_read_seq(seq)
            cid = _require_id(card_id, "card_id")
            return cid in self._published_cards

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: audit rows, in order."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(dict(row) for row in self._audit)

    def _require_read_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read: small numeric summary of the ledger."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "n_cards": len(self._cards),
                "n_publications": len(self._publications),
                "n_audit_rows": len(self._audit),
            }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Model-card self-check: create, publish, verify, pins, audit."""
    ledger = ModelCard()
    ledger.create(
        "card-1", 1, model_id="model-1", intended_use="classification",
        limitations=("data-bias",), metrics=(("accuracy", 0.92),),
    )
    ledger.publish("card-1", 2)
    report = ledger.verify("card-1", 2)
    assert report.verify()
    assert report.published is True
    assert report.integrity_ok is True
    assert ledger.stats(2)["n_cards"] == 1
    print("model-card OK: create, publish, verify, pins, audit")


if __name__ == "__main__":
    main()
