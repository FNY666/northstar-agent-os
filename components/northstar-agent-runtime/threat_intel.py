"""Cyber Threat Intelligence (CTI) lifecycle as a deterministic single-host decision ledger.

Research note: CTI platforms (MISP, OpenCTI, ThreatConnect) follow a
collect -> enrich -> analyze -> disseminate cycle. Indicators of
Compromise (IoCs) — hashes, IPs, domains, YARA signatures — are shared
in STIX/TAXII bundles, scored by severity/confidence, and correlated
against sightings. This module is the bookkeeping layer for that
lifecycle: it books declared collections, host-declared analysis
decisions, and declared sharing events. It performs no network
collection, computes no real threat scores, and contacts no feed.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``threat-intel.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only + ``canonical_json``
try/except fallback, ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events.

Honest scope: a booked indicator or verdict is host-reported data. A
booked ``high`` severity means "the host declared high severity", never
that a threat is real. ``share()`` books the decision to disseminate;
no bytes leave this process.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex, jcs_dumps
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def jcs_dumps(obj) -> str:  # noqa: D103
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


#: Module version.
THREAT_INTEL_VERSION = "threat-intel.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.threat-intel.v1"

_HASH_DOMAIN = b"northstar.threat-intel.v1\x00"

#: Pinned indicator-type vocabulary.
INDICATOR_TYPES = (
    "ip",
    "domain",
    "url",
    "hash",
    "yara",
    "email",
    "file-name",
    "asn",
)

#: Pinned confidence vocabulary.
CONFIDENCE_LEVELS = ("low", "medium", "high")

#: Pinned verdict vocabulary for analysis.
VERDICTS = ("benign", "suspicious", "malicious", "unknown")

#: Pinned channel vocabulary for sharing.
CHANNELS = ("stix", "taxii", "email", "api", "internal")

#: Keys banned from audit details (raw intel content must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "payload", "raw", "content", "ioc", "indicator", "secret", "key",
    "credentials", "password", "token", "sample",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class ThreatIntelError(Exception):
    """Base error for threat-intel misuse."""


class SeqOrderError(ThreatIntelError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(ThreatIntelError):
    """Raised on a malformed indicator or collection id."""


class DuplicateIndicatorError(ThreatIntelError):
    """Raised when an indicator id is already booked."""


class UnknownIndicatorError(ThreatIntelError):
    """Raised when an indicator id is not known."""


class BadTypeError(ThreatIntelError):
    """Raised on an indicator type outside the pinned vocabulary."""


class BadValueError(ThreatIntelError):
    """Raised on a malformed indicator value digest."""


class BadConfidenceError(ThreatIntelError):
    """Raised on a confidence level outside the pinned vocabulary."""


class BadVerdictError(ThreatIntelError):
    """Raised on a verdict outside the pinned vocabulary."""


class BadChannelError(ThreatIntelError):
    """Raised on a share channel outside the pinned vocabulary."""


class DuplicateShareError(ThreatIntelError):
    """Raised when an indicator was already shared to the same channel."""


class AuditKindError(ThreatIntelError):
    """Raised on an unknown audit kind."""


# ---------------------------------------------------------------------------
# Digest helper
# ---------------------------------------------------------------------------

def _digest_pin(*parts: str) -> str:
    joined = "\x1f".join(parts)
    import hashlib

    return "sha256:" + hashlib.sha256(_HASH_DOMAIN + joined.encode("utf-8")).hexdigest()


def _record_digest(record_dict: dict) -> str:
    return "sha256:" + jcs_sha256_hex(record_dict)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadValueError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadValueError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IndicatorRecord:
    """One collected indicator of compromise (value is a digest pin)."""

    indicator_id: str
    indicator_type: str
    value_digest: str
    confidence: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "indicator_id": self.indicator_id,
            "indicator_type": self.indicator_type,
            "value_digest": self.value_digest,
            "confidence": self.confidence,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class AnalysisRecord:
    """One declared analysis decision for an indicator."""

    analysis_id: str
    indicator_id: str
    verdict: str
    confidence: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "analysis_id": self.analysis_id,
            "indicator_id": self.indicator_id,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class ShareRecord:
    """One declared sharing event for an indicator."""

    share_id: str
    indicator_id: str
    channel: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "share_id": self.share_id,
            "indicator_id": self.indicator_id,
            "channel": self.channel,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class IntelReport:
    """Aggregate view: counts per type / verdict / channel."""

    seq: int
    indicators: int
    by_type: tuple
    by_verdict: tuple
    shares: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "indicators": self.indicators,
            "by_type": [list(p) for p in self.by_type],
            "by_verdict": [list(p) for p in self.by_verdict],
            "shares": self.shares,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("collected", "analyzed", "shared", "threat-intel.rejected")


def threat_intel_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw intel keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw intel key banned from audit: {key!r}")
    return {"kind": "threat-intel." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class ThreatIntel:
    """CTI lifecycle ledger: collect -> analyze -> share."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._indicators: dict[str, IndicatorRecord] = {}
        self._analyses: dict[str, AnalysisRecord] = {}
        self._shares: dict[str, ShareRecord] = {}
        self._analysis_ids: list[str] = []
        self._share_ids: list[str] = []
        self._shared_pairs: set[tuple[str, str]] = set()
        self._audit: list[dict] = []
        self._n_rejected = 0

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(threat_intel_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("threat-intel.rejected", {"seq": seq, "reason": reason})

    # -- mutations ------------------------------------------------------
    def collect(self, indicator_id: str, indicator_type: str, seq: int,
                value_digest: str = "", confidence: str = "medium") -> IndicatorRecord:
        """Book one collected indicator. Raw values never enter records."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(indicator_id)
                if indicator_id in self._indicators:
                    raise DuplicateIndicatorError(f"duplicate indicator: {indicator_id!r}")
                if indicator_type not in INDICATOR_TYPES:
                    raise BadTypeError(f"bad indicator type: {indicator_type!r}")
                _check_digest(value_digest)
                if confidence not in CONFIDENCE_LEVELS:
                    raise BadConfidenceError(f"bad confidence: {confidence!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "indicator_id": indicator_id,
                    "indicator_type": indicator_type,
                    "value_digest": value_digest,
                    "confidence": confidence,
                    "seq": seq,
                }
                rec = IndicatorRecord(
                    indicator_id=indicator_id,
                    indicator_type=indicator_type,
                    value_digest=value_digest,
                    confidence=confidence,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._indicators[indicator_id] = rec
                self._emit("collected", {
                    "indicator_id": indicator_id,
                    "indicator_type": indicator_type,
                    "confidence": confidence,
                    "seq": seq,
                })
                return rec
            except ThreatIntelError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def analyze(self, indicator_id: str, seq: int, verdict: str = "unknown",
                confidence: str = "medium") -> AnalysisRecord:
        """Book one declared analysis decision for a collected indicator."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(indicator_id)
                if indicator_id not in self._indicators:
                    raise UnknownIndicatorError(f"unknown indicator: {indicator_id!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                if confidence not in CONFIDENCE_LEVELS:
                    raise BadConfidenceError(f"bad confidence: {confidence!r}")
                analysis_id = f"ana-{len(self._analysis_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "analysis_id": analysis_id,
                    "indicator_id": indicator_id,
                    "verdict": verdict,
                    "confidence": confidence,
                    "seq": seq,
                }
                rec = AnalysisRecord(
                    analysis_id=analysis_id,
                    indicator_id=indicator_id,
                    verdict=verdict,
                    confidence=confidence,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._analyses[analysis_id] = rec
                self._analysis_ids.append(analysis_id)
                self._emit("analyzed", {
                    "analysis_id": analysis_id,
                    "indicator_id": indicator_id,
                    "verdict": verdict,
                    "seq": seq,
                })
                return rec
            except ThreatIntelError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def share(self, indicator_id: str, channel: str, seq: int) -> ShareRecord:
        """Book one declared sharing event. One share per (indicator, channel)."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(indicator_id)
                if indicator_id not in self._indicators:
                    raise UnknownIndicatorError(f"unknown indicator: {indicator_id!r}")
                if channel not in CHANNELS:
                    raise BadChannelError(f"bad channel: {channel!r}")
                if (indicator_id, channel) in self._shared_pairs:
                    raise DuplicateShareError(
                        f"already shared to {channel!r}: {indicator_id!r}")
                share_id = f"shr-{len(self._share_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "share_id": share_id,
                    "indicator_id": indicator_id,
                    "channel": channel,
                    "seq": seq,
                }
                rec = ShareRecord(
                    share_id=share_id,
                    indicator_id=indicator_id,
                    channel=channel,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._shares[share_id] = rec
                self._share_ids.append(share_id)
                self._shared_pairs.add((indicator_id, channel))
                self._emit("shared", {
                    "share_id": share_id,
                    "indicator_id": indicator_id,
                    "channel": channel,
                    "seq": seq,
                })
                return rec
            except ThreatIntelError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def indicator(self, indicator_id: str, seq: int) -> IndicatorRecord:
        with self._lock:
            self._view_seq(seq)
            _check_id(indicator_id)
            try:
                return self._indicators[indicator_id]
            except KeyError:
                raise UnknownIndicatorError(f"unknown indicator: {indicator_id!r}")

    def analysis(self, analysis_id: str, seq: int) -> AnalysisRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._analyses[analysis_id]
            except KeyError:
                raise UnknownIndicatorError(f"unknown analysis: {analysis_id!r}")

    def analyses_for(self, indicator_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(a for a in self._analysis_ids
                         if self._analyses[a].indicator_id == indicator_id)

    def shares_for(self, indicator_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(s for s in self._share_ids
                         if self._shares[s].indicator_id == indicator_id)

    def indicator_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._indicators)

    def report(self, seq: int) -> IntelReport:
        """Aggregate intel posture report (pure read)."""
        with self._lock:
            self._view_seq(seq)
            by_type: dict[str, int] = {}
            for rec in self._indicators.values():
                by_type[rec.indicator_type] = by_type.get(rec.indicator_type, 0) + 1
            by_verdict: dict[str, int] = {}
            for aid in self._analysis_ids:
                v = self._analyses[aid].verdict
                by_verdict[v] = by_verdict.get(v, 0) + 1
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "indicators": len(self._indicators),
                "by_type": sorted(by_type.items()),
                "by_verdict": sorted(by_verdict.items()),
                "shares": len(self._shares),
            }
            return IntelReport(
                seq=seq,
                indicators=len(self._indicators),
                by_type=tuple(sorted(by_type.items())),
                by_verdict=tuple(sorted(by_verdict.items())),
                shares=len(self._shares),
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "indicators": len(self._indicators),
                "analyses": len(self._analyses),
                "shares": len(self._shares),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    ti = ThreatIntel()
    rec = ti.collect("ioc-1", "domain", 1,
                     value_digest="sha256:" + "a" * 64, confidence="high")
    assert rec.verify()
    ana = ti.analyze("ioc-1", 2, verdict="malicious", confidence="high")
    assert ana.verify()
    shr = ti.share("ioc-1", "stix", 3)
    assert shr.verify()
    rep = ti.report(4)
    assert rep.verify() and rep.indicators == 1 and rep.shares == 1
    print("threat-intel OK: collect, analyze, share, report, pins, audit")


if __name__ == "__main__":
    main()
