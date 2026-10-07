"""model_watermarking: model-watermark ownership-claim lifecycle ledger.

Distinct layer vs ``model_watermark.py`` (the weight-channel / trigger-set
*interface* that performs deterministic LSB bit math and trigger-set
verification): this module is the **registry half** -- it books declared
ownership claims over model identities, their embedding declarations,
retirements, and detection queries, without performing any watermark
math or ever seeing key material.  A booked ``embedded`` row means "the
owner declared model M was marked via channel C under key fingerprint K",
never "these weights provably carry a mark".

Public API:
    ModelWatermarking.register_owner(owner_id, seq, owner_digest="")
    ModelWatermarking.embed(model_id, owner_id, channel, seq, model_digest,
                            key_digest="")
    ModelWatermarking.retire(model_id, seq, reason="manual")
    ModelWatermarking.verify(model_id, seq)
    ModelWatermarking.detect(candidate_digest, seq, channel="")
    ModelWatermarking.detected_ids() / owner_ids / model_ids / stats /
    audit_log
    model_watermarking_audit_event(kind, seq, detail=None)

Honest scope: simulated bookkeeping ledger.  Declarations are GIGO host
claims; a ``matched=True`` detection means "the candidate digest equals
a registered model digest", never "the candidate is the watermarked
model".  No wall-clock; no randomness; caller int seqs with
claim-then-burn discipline.
"""
from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # standard sibling fallback
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - fallback path
    import json as _json

    def _jcs_dumps(obj: Any) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)


VERSION = "model-watermarking.v1"
SCHEMA = "northstar.model-watermarking.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_AUDIT_KINDS = (
    "owner-registered",
    "embedded",
    "retired",
    "detected",
    "verified",
    "rejected",
)

# Pinned watermark channel vocabulary: the decision ledger classifies the
# declared embedding technique, it does not run it.
_CHANNELS = (
    "weight-lsb",
    "trigger-set",
    "activation",
    "dataset",
    "black-box",
)

_RETIRE_REASONS = (
    "manual",
    "superseded",
    "compromised",
    "revoked",
    "invalidated",
)

# Raw material that must never cross the audit boundary: only ids, digest
# pins, channels, reasons, and verdicts travel.  Exact-key matching.
_BANNED_KEYS = frozenset({
    "owner", "secret", "model", "key", "weights", "bytes", "raw",
    "payload", "value", "data", "text", "content", "message",
    "trigger", "fingerprint", "params", "layers",
})


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------

class ModelWatermarkingError(Exception):
    """Base error for the model-watermarking ledger."""


class BadIdError(ModelWatermarkingError):
    """Malformed identifier (not a non-empty str of bounded length)."""


class BadDigestError(ModelWatermarkingError):
    """Malformed digest (not ``sha256:<64hex>``)."""


class BadChannelError(ModelWatermarkingError):
    """Unknown watermark channel."""


class BadReasonError(ModelWatermarkingError):
    """Unknown retire reason."""


class DuplicateOwnerError(ModelWatermarkingError):
    """Owner id already registered."""


class UnknownOwnerError(ModelWatermarkingError):
    """No such registered owner."""


class RetiredOwnerError(ModelWatermarkingError):
    """Owner was retired and may never be reused."""


class DuplicateModelError(ModelWatermarkingError):
    """Model id already embedded."""


class RetiredModelError(ModelWatermarkingError):
    """Model id was retired and may never be reused."""


class UnknownModelError(ModelWatermarkingError):
    """No such embedded model."""


class UnknownDetectionError(ModelWatermarkingError):
    """No such booked detection."""


class SeqOrderError(ModelWatermarkingError):
    """Seq not a strictly increasing int."""


class AuditKindError(ModelWatermarkingError):
    """Unknown audit kind or malformed audit row."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _digest_pin(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def _check_id(value: Any, name: str = "id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"bad {name}")
    if value.strip() != value or any(c.isspace() for c in value):
        raise BadIdError(f"bad {name}")
    return value


def _check_digest(value: Any, name: str = "digest") -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"bad {name}")
    if not re.match(r"^sha256:[0-9a-f]{64}$", value):
        raise BadDigestError(f"bad {name}")
    return value


def _check_channel(value: Any) -> str:
    if not isinstance(value, str) or value not in _CHANNELS:
        raise BadChannelError(f"bad channel: {value!r}")
    return value


def _check_channel_filter(value: Any) -> str:
    if value == "":
        return ""
    return _check_channel(value)


def _check_reason(value: Any) -> str:
    if not isinstance(value, str) or value not in _RETIRE_REASONS:
        raise BadReasonError(f"bad reason: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("bad seq")
    return seq


def model_watermarking_audit_event(kind: str, seq: int,
                                   detail: Optional[Dict[str, Any]] = None
                                   ) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the ledger.

    The first parameter is deliberately named ``kind`` here because the
    audit builder owns this namespace; callers pass ``audit_kind``
    positionally to the internal ``_emit`` helper to avoid the known
    sibling ``kind=kind`` collision.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown kind: {kind!r}")
    seq = _check_seq(seq)
    detail = dict(detail or {})
    for key in detail:
        if key in _BANNED_KEYS:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    row = {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": "model_watermarking",
        "detail": detail,
    }
    row["digest"] = _digest_pin(_jcs_dumps(row))
    return row


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OwnerRecord:
    owner_id: str
    owner_digest: str
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"owner_id": self.owner_id,
                "owner_digest": self.owner_digest,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"owner_id": self.owner_id,
                "owner_digest": self.owner_digest, "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class EmbedRecord:
    model_id: str
    owner_id: str
    channel: str
    model_digest: str
    key_digest: str
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"model_id": self.model_id, "owner_id": self.owner_id,
                "channel": self.channel, "model_digest": self.model_digest,
                "key_digest": self.key_digest,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"model_id": self.model_id, "owner_id": self.owner_id,
                "channel": self.channel, "model_digest": self.model_digest,
                "key_digest": self.key_digest, "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    reason: str
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"model_id": self.model_id, "reason": self.reason,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"model_id": self.model_id, "reason": self.reason,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class DetectionReport:
    detection_id: str
    candidate_digest: str
    channel_filter: str
    matched_ids: Tuple[str, ...]
    matched: bool
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"detection_id": self.detection_id,
                "candidate_digest": self.candidate_digest,
                "channel_filter": self.channel_filter,
                "matched_ids": list(self.matched_ids),
                "matched": self.matched,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"detection_id": self.detection_id,
                "candidate_digest": self.candidate_digest,
                "channel_filter": self.channel_filter,
                "matched_ids": list(self.matched_ids),
                "matched": self.matched, "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class VerifyReport:
    model_id: str
    ok: bool
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"model_id": self.model_id, "ok": self.ok,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"model_id": self.model_id, "ok": self.ok,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------

class ModelWatermarking:
    """Deterministic single-host model-watermark ownership-claim ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._owners: Dict[str, OwnerRecord] = {}
        self._retired_owners: set = set()
        self._embeds: Dict[str, EmbedRecord] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._detections: Dict[str, DetectionReport] = {}
        self._det_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline: claim-then-burn -------------------------------

    def _claim(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        self._audit.append(model_watermarking_audit_event(
            audit_kind, self._seq, detail))

    def _reject(self, detail: Dict[str, Any]) -> None:
        self._audit.append(model_watermarking_audit_event(
            "rejected", self._seq, detail))

    # -- API ------------------------------------------------------------

    def register_owner(self, owner_id: str, seq: int,
                       owner_digest: str = "") -> OwnerRecord:
        """Declare a watermarking principal; digest pin only, never a key."""
        with self._lock:
            self._claim(seq)
            try:
                owner_id = _check_id(owner_id, "owner_id")
                if owner_id in self._owners:
                    raise DuplicateOwnerError(
                        f"duplicate owner: {owner_id!r}")
                if owner_id in self._retired_owners:
                    raise RetiredOwnerError(
                        f"retired owner: {owner_id!r}")
                owner_digest = _check_digest(owner_digest, "owner_digest") \
                    if owner_digest else _digest_pin(
                        "model-watermarking-owner:" + owner_id)
                body = {"owner_id": owner_id,
                        "owner_digest": owner_digest, "schema": SCHEMA}
                rec = OwnerRecord(owner_id=owner_id,
                                  owner_digest=owner_digest,
                                  digest=_digest_pin(_jcs_dumps(body)))
                self._owners[owner_id] = rec
                self._emit("owner-registered", {"owner_id": owner_id,
                                               "owner_digest": owner_digest})
                return rec
            except ModelWatermarkingError:
                self._reject({"op": "register_owner",
                              "owner_id": str(owner_id)})
                raise

    def retire_owner(self, owner_id: str, seq: int) -> OwnerRecord:
        """Retire an owner: terminal, ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                owner_id = _check_id(owner_id, "owner_id")
                rec = self._owners.get(owner_id)
                if rec is None:
                    raise UnknownOwnerError(f"unknown owner: {owner_id!r}")
                del self._owners[owner_id]
                self._retired_owners.add(owner_id)
                self._emit("retired", {"owner_id": owner_id})
                return rec
            except ModelWatermarkingError:
                self._reject({"op": "retire_owner",
                              "owner_id": str(owner_id)})
                raise

    def embed(self, model_id: str, owner_id: str, channel: str, seq: int,
              model_digest: str, key_digest: str = "") -> EmbedRecord:
        """Book the *declared* embedding of a watermark mark into a model.

        ``model_digest`` and ``key_digest`` are ``sha256:`` pins only; raw
        weights and raw key material never enter a record.
        """
        with self._lock:
            self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                owner_id = _check_id(owner_id, "owner_id")
                channel = _check_channel(channel)
                if owner_id in self._retired_owners:
                    raise RetiredOwnerError(
                        f"retired owner: {owner_id!r}")
                if owner_id not in self._owners:
                    raise UnknownOwnerError(f"unknown owner: {owner_id!r}")
                if model_id in self._retired:
                    raise RetiredModelError(
                        f"retired model: {model_id!r}")
                if model_id in self._embeds:
                    raise DuplicateModelError(
                        f"duplicate model: {model_id!r}")
                model_digest = _check_digest(model_digest, "model_digest")
                key_digest = _check_digest(key_digest, "key_digest") \
                    if key_digest else _digest_pin(
                        "model-watermarking-key:" + model_id)
                body = {"model_id": model_id, "owner_id": owner_id,
                        "channel": channel, "model_digest": model_digest,
                        "key_digest": key_digest, "schema": SCHEMA}
                rec = EmbedRecord(model_id=model_id, owner_id=owner_id,
                                  channel=channel,
                                  model_digest=model_digest,
                                  key_digest=key_digest,
                                  digest=_digest_pin(_jcs_dumps(body)))
                self._embeds[model_id] = rec
                self._emit("embedded", {"model_id": model_id,
                                        "owner_id": owner_id,
                                        "channel": channel})
                return rec
            except ModelWatermarkingError:
                self._reject({"op": "embed",
                              "model_id": str(model_id)})
                raise

    def retire(self, model_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Retire a watermarked model claim: terminal, ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                reason = _check_reason(reason)
                rec = self._embeds.get(model_id)
                if rec is None:
                    if model_id in self._retired:
                        raise RetiredModelError(
                            f"already retired: {model_id!r}")
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                del self._embeds[model_id]
                body = {"model_id": model_id, "reason": reason,
                        "schema": SCHEMA}
                rrec = RetireRecord(model_id=model_id, reason=reason,
                                    digest=_digest_pin(_jcs_dumps(body)))
                self._retired[model_id] = rrec
                self._emit("retired", {"model_id": model_id,
                                      "reason": reason})
                return rrec
            except ModelWatermarkingError:
                self._reject({"op": "retire",
                              "model_id": str(model_id)})
                raise

    def verify(self, model_id: str, seq: int) -> VerifyReport:
        """Re-walk one embedded claim's digest pins (tamper check).

        Pure read semantics except that the seq must strictly increase and
        the check is booked in the audit log; a tampered record reports
        ``ok=False`` as data, never raised.
        """
        with self._lock:
            self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                rec = self._embeds.get(model_id)
                if rec is None:
                    raise UnknownModelError(f"unknown model: {model_id!r}")
                ok = rec.verify()
                body = {"model_id": model_id, "ok": ok, "schema": SCHEMA}
                report = VerifyReport(model_id=model_id, ok=ok,
                                      digest=_digest_pin(_jcs_dumps(body)))
                self._emit("verified", {"model_id": model_id, "ok": ok})
                return report
            except ModelWatermarkingError:
                self._reject({"op": "verify",
                              "model_id": str(model_id)})
                raise

    def detect(self, candidate_digest: str, seq: int,
               channel: str = "") -> DetectionReport:
        """Book a detection query over a candidate model digest pin.

        ``matched`` is booked **as data**: a match means the candidate
        digest equals a live registered model digest, never that the
        candidate really carries the owner's mark.  No match is booked as
        ``matched=False`` with an empty id list, never raised.
        """
        with self._lock:
            self._claim(seq)
            try:
                candidate_digest = _check_digest(candidate_digest,
                                                "candidate_digest")
                channel = _check_channel_filter(channel)
                hits = tuple(sorted(
                    m for m, r in self._embeds.items()
                    if r.model_digest == candidate_digest
                    and (channel == "" or r.channel == channel)))
                matched = bool(hits)
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                body = {"detection_id": detection_id,
                        "candidate_digest": candidate_digest,
                        "channel_filter": channel,
                        "matched_ids": list(hits),
                        "matched": matched, "schema": SCHEMA}
                report = DetectionReport(
                    detection_id=detection_id,
                    candidate_digest=candidate_digest,
                    channel_filter=channel, matched_ids=hits,
                    matched=matched,
                    digest=_digest_pin(_jcs_dumps(body)))
                self._detections[detection_id] = report
                self._emit("detected", {"detection_id": detection_id,
                                        "channel_filter": channel,
                                        "matched": matched,
                                        "hits": len(hits)})
                return report
            except ModelWatermarkingError:
                self._reject({"op": "detect",
                              "channel_filter": str(channel)})
                raise

    # -- pure-read views (validate seq shape, never consume, no audit) --

    def owner_record(self, owner_id: str, seq: int) -> OwnerRecord:
        with self._lock:
            _check_seq(seq)
            owner_id = _check_id(owner_id, "owner_id")
            rec = self._owners.get(owner_id)
            if rec is None:
                raise UnknownOwnerError(f"unknown owner: {owner_id!r}")
            return rec

    def embed_record(self, model_id: str, seq: int) -> EmbedRecord:
        with self._lock:
            _check_seq(seq)
            model_id = _check_id(model_id, "model_id")
            rec = self._embeds.get(model_id)
            if rec is None:
                raise UnknownModelError(f"unknown model: {model_id!r}")
            return rec

    def detection_record(self, detection_id: str,
                         seq: int) -> DetectionReport:
        with self._lock:
            _check_seq(seq)
            detection_id = _check_id(detection_id, "detection_id")
            rec = self._detections.get(detection_id)
            if rec is None:
                raise UnknownDetectionError(
                    f"unknown detection: {detection_id!r}")
            return rec

    def owner_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._owners))

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._embeds))

    def detected_ids(self, seq: int) -> Tuple[str, ...]:
        """Detection ids whose booked verdict was ``matched=True``."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(
                d for d, r in self._detections.items() if r.matched))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            _check_seq(seq)
            return {"owners": len(self._owners),
                    "embedded": len(self._embeds),
                    "retired": len(self._retired),
                    "detections": len(self._detections),
                    "matched": len([r for r in self._detections.values()
                                    if r.matched]),
                    "seq": self._seq}

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    mw = ModelWatermarking()
    o = mw.register_owner("vendor-a", 1)
    assert o.verify()
    model_digest = "sha256:" + "ab" * 32
    e = mw.embed("llama-x-1", "vendor-a", "weight-lsb", 2,
                 model_digest=model_digest)
    assert e.verify() and e.channel == "weight-lsb"
    d = mw.detect(model_digest, 3)
    assert d.matched and d.matched_ids == ("llama-x-1",) and d.verify()
    d2 = mw.detect("sha256:" + "00" * 32, 4)
    assert not d2.matched and d2.matched_ids == ()
    r = mw.retire("llama-x-1", 5)
    assert r.verify() and r.reason == "manual"
    assert mw.detected_ids(6) == ("det-1",)
    print("model-watermarking OK: register, embed, detect, retire, pins, audit")


if __name__ == "__main__":
    main()
