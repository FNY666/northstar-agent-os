"""attribution.py — source-attribution bookkeeping for content provenance.

Research context: source attribution for AI-generated and mixed-origin content.
This module is the attribution-assertion layer: declare sources, book
attribution links between content items and sources, and verify those links.

It is deliberately distinct from the sibling batch-48 modules:
``watermark.py`` owns signal embed/detect, ``provenance.py`` owns
attest/verify/trace, ``c2pa.py`` owns manifests, and ``deepfake_detection.py``
owns synthetic-media scoring. This module owns the *attribution decision* —
who or what a content item is attributed to — as a deterministic single-host
state machine.

Simulated: the ledger books host-declared sources and attribution links; it
cannot observe the real provenance of a byte stream and cannot prove a
content item really originated from its attributed source (the GIGO boundary
shared with every other bookkeeping module in this repo). A booked
attribution is ledger truth, never proof of origin.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    _jcs_dumps = None  # type: ignore

VERSION = "attribution.v1"
SCHEMA = "northstar.attribution.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_INT = 2 ** 53
_MAX_ID_LEN = 128

SOURCE_KINDS = (
    "human-author",
    "ai-model",
    "organization",
    "automated-pipeline",
    "data-corpus",
    "third-party",
)

LINK_METHODS = (
    "watermark",
    "c2pa-manifest",
    "metadata",
    "provenance-graph",
    "human-declaration",
    "model-report",
)

RETIRE_REASONS = (
    "manual",
    "superseded",
    "revoked",
    "invalidated",
)

AUDIT_KINDS = (
    "source-declared",
    "linked",
    "retired",
    "attribution.rejected",
)


class AttributionError(Exception):
    """Base for all attribution errors."""


class BadIdError(AttributionError):
    pass


class DuplicateSourceError(AttributionError):
    pass


class UnknownSourceError(AttributionError):
    pass


class RetiredSourceError(AttributionError):
    pass


class DuplicateLinkError(AttributionError):
    pass


class UnknownLinkError(AttributionError):
    pass


class BadKindError(AttributionError):
    pass


class BadMethodError(AttributionError):
    pass


class BadConfidenceError(AttributionError):
    pass


class BadDigestError(AttributionError):
    pass


class BadReasonError(AttributionError):
    pass


class SeqOrderError(AttributionError):
    pass


class AuditKindError(AttributionError):
    pass


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{what} must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{what} must be a non-empty str of <= {_MAX_ID_LEN} chars")
    return value


def _check_kind(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadKindError(f"kind must be a str, got {type(value).__name__}")
    if value not in SOURCE_KINDS:
        raise BadKindError(f"kind {value!r} not in pinned vocabulary")
    return value


def _check_method(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadMethodError(f"method must be a str, got {type(value).__name__}")
    if value not in LINK_METHODS:
        raise BadMethodError(f"method {value!r} not in pinned vocabulary")
    return value


def _check_reason(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReasonError(f"reason must be a str, got {type(value).__name__}")
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason {value!r} not in pinned vocabulary")
    return value


def _check_confidence(value: Any) -> float:
    if isinstance(value, bool):
        raise BadConfidenceError("confidence must not be a bool")
    if isinstance(value, int):
        if value not in (0, 1):
            raise BadConfidenceError("integer confidence must be 0 or 1")
        return float(value)
    if not isinstance(value, float):
        raise BadConfidenceError(
            f"confidence must be a float, got {type(value).__name__}"
        )
    if value != value or value in (float("inf"), float("-inf")):
        raise BadConfidenceError("confidence must be finite")
    if not 0.0 <= value <= 1.0:
        raise BadConfidenceError("confidence must be in [0, 1]")
    return value


def _check_digest_pin(value: Any, what: str, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if allow_empty and value == "":
        return value
    if len(value) != len(_DIGEST_PREFIX) + 64 or not value.startswith(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a {_DIGEST_PREFIX}<64hex> pin")
    body = value[len(_DIGEST_PREFIX) :]
    if any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError(f"{what} must be lowercase hex")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _jcs_dumps is not None:
        return _jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise AttributionError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise AttributionError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise AttributionError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRecord:
    """One booked attribution source declaration."""

    source_id: str
    kind: str
    detail_digest: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "kind": self.kind,
            "detail_digest": self.detail_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.source_id, self.kind, self.detail_digest), "source"
        )
        return self.digest == expect


@dataclass(frozen=True)
class LinkRecord:
    """One booked attribution link between a content item and a source."""

    content_id: str
    source_id: str
    method: str
    confidence: float
    content_digest: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "source_id": self.source_id,
            "method": self.method,
            "confidence": self.confidence,
            "content_digest": self.content_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.content_id,
                self.source_id,
                self.method,
                self.confidence,
                self.content_digest,
            ),
            "link",
        )
        return self.digest == expect


@dataclass(frozen=True)
class VerificationReport:
    """One attribution verification; verdicts are data, never raised."""

    content_id: str
    source_id: str
    source_kind: str
    method: str
    confidence: float
    attributed: bool
    integrity_ok: bool
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "method": self.method,
            "confidence": self.confidence,
            "attributed": self.attributed,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.content_id,
                self.source_id,
                self.source_kind,
                self.method,
                self.confidence,
                self.attributed,
                self.integrity_ok,
            ),
            "verification",
        )
        return self.digest == expect


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an attribution source."""

    source_id: str
    reason: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "reason": self.reason,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin((self.source_id, self.reason), "retire")
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def attribution_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw source/content text never crosses this boundary."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "detail",
        "text",
        "content",
        "source",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "justification",
        "explanation",
        "summary",
        "description",
        "transcript",
        "prompt",
        "response",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "attribution",
        "kind": audit_kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((audit_kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Attribution ledger
# ---------------------------------------------------------------------------


class Attribution:
    """Source-attribution bookkeeping: source(), link(), verify(), retire()."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # source_id -> SourceRecord (insertion ordered)
        self._sources: Dict[str, SourceRecord] = {}
        # content_id -> LinkRecord (insertion ordered)
        self._links: Dict[str, LinkRecord] = {}
        # source_id -> RetireRecord
        self._retirements: Dict[str, RetireRecord] = {}
        # retired source ids
        self._retired: set = set()
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            attribution_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: AttributionError, **detail: Any) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def source(
        self, source_id: str, kind: str, seq: int, detail_digest: str = ""
    ) -> SourceRecord:
        """Declare one attribution source. Detail travels as a digest pin only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                source_id = _check_id(source_id, "source_id")
                kind = _check_kind(kind)
                detail_digest = _check_digest_pin(
                    detail_digest, "detail_digest", allow_empty=True
                )
                if source_id in self._retired:
                    raise RetiredSourceError(f"source {source_id!r} retired")
                if source_id in self._sources:
                    raise DuplicateSourceError(f"source {source_id!r} already declared")
            except AttributionError as exc:
                self._fail(seq, exc, source_id=str(source_id))
            record = SourceRecord(
                source_id=source_id,
                kind=kind,
                detail_digest=detail_digest,
                digest=_digest_pin((source_id, kind, detail_digest), "source"),
                seq=seq,
            )
            self._sources[source_id] = record
            self._emit("source-declared", seq, source_id=source_id, kind=kind)
            return record

    def link(
        self,
        content_id: str,
        source_id: str,
        seq: int,
        method: str = "human-declaration",
        confidence: float = 1.0,
        content_digest: str = "",
    ) -> LinkRecord:
        """Book one attribution link between a content item and a declared source.

        The link is an assertion, not proof of origin. The source must be
        declared and not retired. One content item holds at most one link.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                content_id = _check_id(content_id, "content_id")
                source_id = _check_id(source_id, "source_id")
                method = _check_method(method)
                confidence = _check_confidence(confidence)
                content_digest = _check_digest_pin(
                    content_digest, "content_digest", allow_empty=True
                )
                if source_id in self._retired:
                    raise RetiredSourceError(f"source {source_id!r} retired")
                if source_id not in self._sources:
                    raise UnknownSourceError(f"source {source_id!r} not declared")
                if content_id in self._links:
                    raise DuplicateLinkError(
                        f"content {content_id!r} already attributed"
                    )
            except AttributionError as exc:
                self._fail(
                    seq, exc, content_id=str(content_id), source_id=str(source_id)
                )
            record = LinkRecord(
                content_id=content_id,
                source_id=source_id,
                method=method,
                confidence=confidence,
                content_digest=content_digest,
                digest=_digest_pin(
                    (content_id, source_id, method, confidence, content_digest),
                    "link",
                ),
                seq=seq,
            )
            self._links[content_id] = record
            self._emit(
                "linked",
                seq,
                content_id=content_id,
                source_id=source_id,
                method=method,
                confidence=confidence,
            )
            return record

    def retire(self, source_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal retirement of an attribution source; the id is never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                source_id = _check_id(source_id, "source_id")
                reason = _check_reason(reason)
                if source_id in self._retired:
                    raise RetiredSourceError(f"source {source_id!r} already retired")
                if source_id not in self._sources:
                    raise UnknownSourceError(f"source {source_id!r} not declared")
            except AttributionError as exc:
                self._fail(seq, exc, source_id=str(source_id))
            record = RetireRecord(
                source_id=source_id,
                reason=reason,
                digest=_digest_pin((source_id, reason), "retire"),
                seq=seq,
            )
            self._retired.add(source_id)
            self._retirements[source_id] = record
            self._emit("retired", seq, source_id=source_id, reason=reason)
            return record

    # -- views (pure reads: validate seq shape, never consume, no audit rows) --

    def verify(self, content_id: str, seq: int) -> VerificationReport:
        """Verify one attribution link. Verdicts are data: unknown content or a
        retired source reports ``attributed=False``; digest-pin failures report
        ``integrity_ok=False``. Nothing is raised for absent attributions."""
        with self._lock:
            _check_seq(seq)
            _check_id(content_id, "content_id")
            link = self._links.get(content_id)
            if link is None:
                attributed = False
                integrity_ok = True
                source_id = ""
                source_kind = ""
                method = ""
                confidence = 0.0
            else:
                source_id = link.source_id
                src = self._sources.get(source_id)
                source_kind = src.kind if src is not None else ""
                method = link.method
                confidence = link.confidence
                integrity_ok = link.verify()
                if src is not None:
                    integrity_ok = integrity_ok and src.verify()
                attributed = (
                    source_id not in self._retired
                    and src is not None
                    and integrity_ok
                )
            report = VerificationReport(
                content_id=content_id,
                source_id=source_id,
                source_kind=source_kind,
                method=method,
                confidence=confidence,
                attributed=attributed,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    (
                        content_id,
                        source_id,
                        source_kind,
                        method,
                        confidence,
                        attributed,
                        integrity_ok,
                    ),
                    "verification",
                ),
                seq=seq,
            )
            return report

    def source_record(self, source_id: str, seq: int) -> SourceRecord:
        _check_seq(seq)
        _check_id(source_id, "source_id")
        if source_id not in self._sources:
            raise UnknownSourceError(f"source {source_id!r} not declared")
        return self._sources[source_id]

    def source_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._sources)

    def link_record(self, content_id: str, seq: int) -> LinkRecord:
        _check_seq(seq)
        _check_id(content_id, "content_id")
        if content_id not in self._links:
            raise UnknownLinkError(f"content {content_id!r} not attributed")
        return self._links[content_id]

    def link_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._links)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, int]:
        _check_seq(seq)
        return {
            "sources": len(self._sources),
            "links": len(self._links),
            "retired": len(self._retired),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    at = Attribution()
    rec = at.source("claude-opus", "ai-model", 1)
    assert rec.verify() and rec.kind == "ai-model"
    assert rec.digest.startswith(_DIGEST_PREFIX)
    link = at.link("article-001", "claude-opus", 2, method="watermark", confidence=0.9)
    assert link.verify() and link.confidence == 0.9
    rep = at.verify("article-001", 3)
    assert rep.verify() and rep.attributed is True
    assert rep.source_kind == "ai-model" and rep.integrity_ok is True
    # unknown content reports attributed=False as data
    rep2 = at.verify("never-seen", 4)
    assert rep2.verify() and rep2.attributed is False
    try:
        at.link("article-001", "claude-opus", 5)
    except DuplicateLinkError:
        pass
    else:
        raise AssertionError("duplicate link accepted")
    try:
        at.link("article-002", "no-such-source", 6)
    except UnknownSourceError:
        pass
    else:
        raise AssertionError("unknown source link accepted")
    try:
        at.source("claude-opus", "ai-model", 7)
    except DuplicateSourceError:
        pass
    else:
        raise AssertionError("duplicate source accepted")
    ret = at.retire("claude-opus", 8, reason="superseded")
    assert ret.verify()
    rep3 = at.verify("article-001", 9)
    assert rep3.verify() and rep3.attributed is False
    try:
        at.link("article-003", "claude-opus", 10)
    except RetiredSourceError:
        pass
    else:
        raise AssertionError("link to retired source accepted")
    try:
        at.source("claude-opus", "ai-model", 11)
    except RetiredSourceError:
        pass
    else:
        raise AssertionError("re-source of retired id accepted")
    at2 = Attribution()
    at2.source("b", "human-author", 1)
    at2.source("a", "organization", 2)
    assert at2.stats(3)["sources"] == 2
    print("attribution OK: source, link, verify, retire, refusals")


if __name__ == "__main__":
    main()
