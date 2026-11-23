"""Synthetic media — synthetic-content generation/label/disclosure ledger.

Research note (synthetic-content disclosure literature): the EU AI Act
Art. 50 requires providers of AI systems that generate synthetic
text/image/audio/video to disclose the artificial origin in a
machine-readable way; C2PA (Coalition for Content Provenance and
Authenticity) standardises content-credential manifests; watermarking
literature (Kirchenbauer et al. 2023 for text, SynthID for images)
distinguishes *embedded* markers from *visible* labels. This module
takes the intersection for a single-host deterministic ledger:

* **Declarations, not pixels**: ``generate`` books the declaration of
  one synthetic artifact (kind, prompt digest, provenance linkage).
  No bytes are stored, rendered, or detected — digests only.
* **Labels as decisions**: ``label`` books a classification decision
  over a pinned label vocabulary (ai-generated / ai-edited /
  deepfake / parody / watermarked) as data.
* **Disclosure as data**: ``disclose`` books one disclosure event on
  a pinned channel vocabulary (embedded-metadata / visible-label /
  c2pa-manifest / platform-tag). Whether a human ever saw the label
  is host-reported GIGO.
* **Retirement**: ``retire`` ends an artifact's lifecycle terminally.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq via the
claim-then-burn discipline; rewinds raise bare), RLock-guarded,
fail-closed taxonomy, stdlib-only (``canonical_json`` sibling helper
behind the standard try/except fallback), sha256 digest pins over
type-tagged canonical payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* generations, labels,
and disclosures deterministically. It generates no content, applies
no watermark, detects no deepfakes, and cannot prove a label was
ever displayed to a viewer. A ``disclosed`` record means "the host
declared the disclosure channel", never "a human saw the label".
Production still needs a real generator, a real watermark embedder,
a C2PA manifest signer, and platform-side enforcement.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
SYNTHETIC_MEDIA_VERSION = "synthetic-media.v1"

#: Schema pin carried by records and audit events.
SYNTHETIC_MEDIA_SCHEMA = "northstar.synthetic-media.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

# ---------------------------------------------------------------------------
# Pinned vocabularies
# ---------------------------------------------------------------------------

KIND_TEXT = "text"
KIND_IMAGE = "image"
KIND_AUDIO = "audio"
KIND_VIDEO = "video"
MEDIA_KINDS = (KIND_TEXT, KIND_IMAGE, KIND_AUDIO, KIND_VIDEO)

LABEL_AI_GENERATED = "ai-generated"
LABEL_AI_EDITED = "ai-edited"
LABEL_DEEPFAKE = "deepfake"
LABEL_PARODY = "parody"
LABEL_WATERMARKED = "watermarked"
LABELS = (
    LABEL_AI_GENERATED,
    LABEL_AI_EDITED,
    LABEL_DEEPFAKE,
    LABEL_PARODY,
    LABEL_WATERMARKED,
)

CHANNEL_EMBEDDED = "embedded-metadata"
CHANNEL_VISIBLE = "visible-label"
CHANNEL_C2PA = "c2pa-manifest"
CHANNEL_PLATFORM = "platform-tag"
DISCLOSURE_CHANNELS = (
    CHANNEL_EMBEDDED,
    CHANNEL_VISIBLE,
    CHANNEL_C2PA,
    CHANNEL_PLATFORM,
)

RETIRE_REASONS = ("manual", "superseded", "invalidated")

AUDIT_KINDS = (
    "generated",
    "labeled",
    "disclosed",
    "retired",
    "rejected",
)

# Keys that must never cross the audit boundary (raw content material).
BANNED_AUDIT_KEYS = frozenset({
    "prompt", "output", "text", "image", "audio", "video",
    "payload", "raw", "value", "data", "content", "bytes",
})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SyntheticMediaError(Exception):
    """Base error for synthetic media bookkeeping."""


class BadMediaError(SyntheticMediaError):
    pass


class DuplicateMediaError(SyntheticMediaError):
    pass


class UnknownMediaError(SyntheticMediaError):
    pass


class RetiredMediaError(SyntheticMediaError):
    pass


class BadKindError(SyntheticMediaError):
    pass


class BadLabelError(SyntheticMediaError):
    pass


class BadChannelError(SyntheticMediaError):
    pass


class BadReasonError(SyntheticMediaError):
    pass


class BadDigestError(SyntheticMediaError):
    pass


class SeqOrderError(SyntheticMediaError):
    pass


class AuditKindError(SyntheticMediaError):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical(payload: Mapping[str, Any]) -> bytes:
    """JCS-canonical bytes for digest pinning (sibling-first, stdlib fallback)."""
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _norm(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _norm(value[k]) for k in sorted(value)}
        if isinstance(value, (list, tuple)):
            return [_norm(v) for v in value]
        if isinstance(value, float):
            raise ValueError("floats not canonicalizable")
        return value

    return json.dumps(_norm(dict(payload)), separators=(",", ":")).encode("utf-8")


def _digest_pin(type_tag: str, payload: Mapping[str, Any]) -> str:
    """sha256 digest pin over a type-tagged canonical payload."""
    body = type_tag.encode("utf-8") + b":" + _canonical(payload)
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _check_digest(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise BadDigestError(f"digest must be a 'sha256:<64hex>' pin, got {value!r}")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"digest hex invalid: {value!r}")
    return value


def _check_id(value: Any, name: str = "media_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadMediaError(f"{name} must be a non-empty str <= 128 chars")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GenerationRecord:
    """One declared synthetic-media generation."""

    media_id: str
    kind: str
    prompt_digest: str
    output_digest: str
    provenance: Tuple[str, ...]
    seq: int
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SYNTHETIC_MEDIA_SCHEMA,
            "version": SYNTHETIC_MEDIA_VERSION,
            "media_id": self.media_id,
            "kind": self.kind,
            "prompt_digest": self.prompt_digest,
            "output_digest": self.output_digest,
            "provenance": list(self.provenance),
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "synthetic-media.generation",
            {
                "media_id": self.media_id,
                "kind": self.kind,
                "prompt_digest": self.prompt_digest,
                "output_digest": self.output_digest,
                "provenance": list(self.provenance),
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class LabelRecord:
    """One declared classification label on a synthetic artifact."""

    label_id: str
    media_id: str
    label: str
    seq: int
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SYNTHETIC_MEDIA_SCHEMA,
            "version": SYNTHETIC_MEDIA_VERSION,
            "label_id": self.label_id,
            "media_id": self.media_id,
            "label": self.label,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "synthetic-media.label",
            {
                "label_id": self.label_id,
                "media_id": self.media_id,
                "label": self.label,
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class DisclosureRecord:
    """One declared disclosure event for a synthetic artifact."""

    disclosure_id: str
    media_id: str
    channel: str
    seq: int
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SYNTHETIC_MEDIA_SCHEMA,
            "version": SYNTHETIC_MEDIA_VERSION,
            "disclosure_id": self.disclosure_id,
            "media_id": self.media_id,
            "channel": self.channel,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "synthetic-media.disclosure",
            {
                "disclosure_id": self.disclosure_id,
                "media_id": self.media_id,
                "channel": self.channel,
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a synthetic-media artifact."""

    media_id: str
    reason: str
    seq: int
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SYNTHETIC_MEDIA_SCHEMA,
            "version": SYNTHETIC_MEDIA_VERSION,
            "media_id": self.media_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            "synthetic-media.retire",
            {"media_id": self.media_id, "reason": self.reason, "seq": self.seq},
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class SyntheticMedia:
    """Synthetic-content generation/label/disclosure ledger (simulated)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._generations: Dict[str, GenerationRecord] = {}
        self._labels: Dict[str, LabelRecord] = {}
        self._disclosures: Dict[str, DisclosureRecord] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._label_seq = 0
        self._disclosure_seq = 0
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._seq}, got={seq})"
                )
            self._seq = seq
            return seq

    def _burn(self, seq: int, error: SyntheticMediaError) -> SyntheticMediaError:
        """Book a rejected row for a failed mutation (claim-then-burn)."""
        with self._lock:
            self._audit.append(
                {
                    "schema": AUDIT_SCHEMA,
                    "kind": "rejected",
                    "module": SYNTHETIC_MEDIA_SCHEMA,
                    "seq": seq,
                    "detail": {"error": type(error).__name__},
                }
            )
        return error

    # -- audit --------------------------------------------------------------

    def _audit_row(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        if kind not in AUDIT_KINDS:
            raise AuditKindError(f"unknown audit kind: {kind!r}")
        clean = {k: v for k, v in detail.items() if k not in BANNED_AUDIT_KEYS}
        with self._lock:
            self._audit.append(
                {
                    "schema": AUDIT_SCHEMA,
                    "kind": kind,
                    "module": SYNTHETIC_MEDIA_SCHEMA,
                    "seq": seq,
                    "detail": clean,
                }
            )

    def _require_live(self, media_id: str) -> GenerationRecord:
        media_id = _check_id(media_id)
        if media_id in self._retired:
            raise RetiredMediaError(f"media retired: {media_id!r}")
        try:
            return self._generations[media_id]
        except KeyError:
            raise UnknownMediaError(f"unknown media: {media_id!r}")

    # -- API ----------------------------------------------------------------

    def generate(
        self,
        media_id: str,
        kind: str,
        seq: int,
        prompt_digest: str = "",
        output_digest: str = "",
        provenance: Tuple[str, ...] = (),
    ) -> GenerationRecord:
        """Book the declaration of one synthetic artifact generation."""
        seq = self._claim(seq)
        try:
            media_id = _check_id(media_id)
            if kind not in MEDIA_KINDS:
                raise BadKindError(f"kind must be one of {MEDIA_KINDS}, got {kind!r}")
            prompt_digest = (
                _check_digest(prompt_digest) if prompt_digest else ""
            )
            output_digest = (
                _check_digest(output_digest) if output_digest else ""
            )
            if media_id in self._retired:
                raise RetiredMediaError(f"media retired: {media_id!r}")
            if media_id in self._generations:
                raise DuplicateMediaError(f"duplicate media: {media_id!r}")
            prov = tuple(_check_id(p, "provenance") for p in provenance)
        except SyntheticMediaError as exc:
            raise self._burn(seq, exc)
        record = GenerationRecord(
            media_id=media_id,
            kind=kind,
            prompt_digest=prompt_digest,
            output_digest=output_digest,
            provenance=prov,
            seq=seq,
            digest=_digest_pin(
                "synthetic-media.generation",
                {
                    "media_id": media_id,
                    "kind": kind,
                    "prompt_digest": prompt_digest,
                    "output_digest": output_digest,
                    "provenance": list(prov),
                    "seq": seq,
                },
            ),
        )
        with self._lock:
            self._generations[media_id] = record
        self._audit_row("generated", seq, {"media_id": media_id, "kind": kind,
                                          "digest": record.digest})
        return record

    def label(self, media_id: str, label: str, seq: int) -> LabelRecord:
        """Book one classification label on a synthetic artifact."""
        seq = self._claim(seq)
        try:
            self._require_live(media_id)
            if label not in LABELS:
                raise BadLabelError(f"label must be one of {LABELS}, got {label!r}")
        except SyntheticMediaError as exc:
            raise self._burn(seq, exc)
        with self._lock:
            self._label_seq += 1
            label_id = f"lbl-{self._label_seq}"
        record = LabelRecord(
            label_id=label_id,
            media_id=media_id,
            label=label,
            seq=seq,
            digest=_digest_pin(
                "synthetic-media.label",
                {"label_id": label_id, "media_id": media_id, "label": label, "seq": seq},
            ),
        )
        with self._lock:
            self._labels[label_id] = record
        self._audit_row("labeled", seq, {"label_id": label_id, "media_id": media_id,
                                        "label": label, "digest": record.digest})
        return record

    def disclose(self, media_id: str, channel: str, seq: int) -> DisclosureRecord:
        """Book one disclosure event for a synthetic artifact."""
        seq = self._claim(seq)
        try:
            self._require_live(media_id)
            if channel not in DISCLOSURE_CHANNELS:
                raise BadChannelError(
                    f"channel must be one of {DISCLOSURE_CHANNELS}, got {channel!r}"
                )
        except SyntheticMediaError as exc:
            raise self._burn(seq, exc)
        with self._lock:
            self._disclosure_seq += 1
            disclosure_id = f"dcl-{self._disclosure_seq}"
        record = DisclosureRecord(
            disclosure_id=disclosure_id,
            media_id=media_id,
            channel=channel,
            seq=seq,
            digest=_digest_pin(
                "synthetic-media.disclosure",
                {
                    "disclosure_id": disclosure_id,
                    "media_id": media_id,
                    "channel": channel,
                    "seq": seq,
                },
            ),
        )
        with self._lock:
            self._disclosures[disclosure_id] = record
        self._audit_row("disclosed", seq, {"disclosure_id": disclosure_id,
                                          "media_id": media_id, "channel": channel,
                                          "digest": record.digest})
        return record

    def retire(self, media_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a synthetic-media artifact."""
        seq = self._claim(seq)
        try:
            self._require_live(media_id)
            if reason not in RETIRE_REASONS:
                raise BadReasonError(
                    f"reason must be one of {RETIRE_REASONS}, got {reason!r}"
                )
        except SyntheticMediaError as exc:
            raise self._burn(seq, exc)
        record = RetireRecord(
            media_id=media_id,
            reason=reason,
            seq=seq,
            digest=_digest_pin(
                "synthetic-media.retire",
                {"media_id": media_id, "reason": reason, "seq": seq},
            ),
        )
        with self._lock:
            self._retired[media_id] = record
        self._audit_row("retired", seq, {"media_id": media_id, "reason": reason,
                                        "digest": record.digest})
        return record

    # -- views (pure reads) ---------------------------------------------------

    def _view_seq(self, seq: int) -> None:
        _check_seq(seq)

    def generation(self, media_id: str, seq: int) -> GenerationRecord:
        self._view_seq(seq)
        return self._require_live(media_id)

    def labels_for(self, media_id: str, seq: int) -> Tuple[LabelRecord, ...]:
        self._view_seq(seq)
        _check_id(media_id)
        with self._lock:
            return tuple(
                sorted(
                    (r for r in self._labels.values() if r.media_id == media_id),
                    key=lambda r: r.label_id,
                )
            )

    def disclosures_for(self, media_id: str, seq: int) -> Tuple[DisclosureRecord, ...]:
        self._view_seq(seq)
        _check_id(media_id)
        with self._lock:
            return tuple(
                sorted(
                    (r for r in self._disclosures.values() if r.media_id == media_id),
                    key=lambda r: r.disclosure_id,
                )
            )

    def media_ids(self, seq: int) -> Tuple[str, ...]:
        self._view_seq(seq)
        with self._lock:
            return tuple(sorted(self._generations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        self._view_seq(seq)
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        self._view_seq(seq)
        with self._lock:
            return {
                "generations": len(self._generations),
                "labels": len(self._labels),
                "disclosures": len(self._disclosures),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
                "last_seq": self._seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        self._view_seq(seq)
        with self._lock:
            return tuple(dict(row) for row in self._audit)


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------

def synthetic_media_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for this module (fail-closed)."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    clean = {k: v for k, v in detail.items() if k not in BANNED_AUDIT_KEYS}
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": SYNTHETIC_MEDIA_SCHEMA,
        "seq": seq,
        "detail": clean,
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    sm = SyntheticMedia()
    pin = "sha256:" + "ab" * 32
    rec = sm.generate("m-1", "image", 1, prompt_digest=pin, output_digest=pin)
    assert rec.verify(), "generation digest must verify"
    lbl = sm.label("m-1", "ai-generated", 2)
    assert lbl.verify(), "label digest must verify"
    dcl = sm.disclose("m-1", "c2pa-manifest", 3)
    assert dcl.verify(), "disclosure digest must verify"
    sm.retire("m-1", 4, "superseded")
    assert sm.stats(4)["retired"] == 1
    try:
        sm.label("m-1", "parody", 5)
    except RetiredMediaError:
        pass
    else:
        raise AssertionError("label on retired media must fail")
    # audit boundary carries digests only
    for row in sm.audit_log(5):
        for key in row["detail"]:
            assert key not in BANNED_AUDIT_KEYS, f"leak: {key}"
    print("synthetic-media OK: generate, label, disclose, retire, pins, audit")


if __name__ == "__main__":
    main()
