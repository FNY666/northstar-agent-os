"""Data export (GDPR portability): request / status / download.

Interface:
    DataExport.request(params)        -> sealed ExportRequest (pending)
    DataExport.status(export_id)      -> sealed status of a request
    DataExport.download(export_id, params) -> sealed data package

The generation itself is simulated: the caller injects a ``data_source``
that supplies the subject's data, and the module serialises it into the
requested ``format`` deterministically (canonical JSON). No wall-clock:
the caller supplies a monotonic ``seq``. Validation is fail-closed:
unknown export ids, subject mismatches, unsupported scopes, and downloads
of non-ready exports are all denied and audited.

House style: frozen dataclasses, stdlib only, audit events as
``audit.ndjson/1`` JSONL lines supplied by the caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Tuple


_EXPORT_AUDIT_TYPE = "audit.ndjson/1"

_VALID_FORMATS = frozenset({"json", "jsonl"})
_VALID_SCOPES = frozenset(
    {
        "profile",
        "identities",
        "sessions",
        "devices",
        "consents",
        "audit",
        "invitations",
        "memberships",
        "preferences",
        "billing",
    }
)


@dataclass(frozen=True)
class ExportParams:
    """Inputs required to request a data export (GDPR Art. 15/20)."""

    subject_id: str
    scopes: Tuple[str, ...] = ()
    format: str = "json"
    requested_at_seq: int = 0
    download_ttl_seq: int = 1_000
    nonce: str = ""

    def validate(self) -> Tuple[bool, str]:
        if not self.subject_id or not self.subject_id.strip():
            return False, "subject_id required"
        if self.format not in _VALID_FORMATS:
            return False, f"unknown format {self.format!r}"
        if not self.scopes:
            return False, "at least one scope required"
        for s in self.scopes:
            if s not in _VALID_SCOPES:
                return False, f"unsupported scope {s!r}"
        if self.requested_at_seq < 0:
            return False, "requested_at_seq must be non-negative"
        if self.download_ttl_seq <= 0:
            return False, "download_ttl_seq must be positive"
        return True, ""


@dataclass(frozen=True)
class DownloadParams:
    """Inputs required to download a prepared export."""

    subject_id: str
    now_seq: int

    def validate(self) -> Tuple[bool, str]:
        if not self.subject_id or not self.subject_id.strip():
            return False, "subject_id required"
        if self.now_seq < 0:
            return False, "now_seq must be non-negative"
        return True, ""


@dataclass(frozen=True)
class ExportRecord:
    """A sealed export request and its lifecycle state."""

    export_id: str
    subject_id: str
    scopes: Tuple[str, ...]
    format: str
    requested_at_seq: int
    ready_at_seq: int
    expires_at_seq: int
    nonce: str
    state: str = "pending"  # pending | ready | delivered | expired
    checksum: str = ""


@dataclass(frozen=True)
class Decision:
    """Sealed outcome of request/status/download."""

    allowed: bool
    reason: str
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "payload": dict(self.payload),
        }

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "Decision":
        return Decision(
            allowed=bool(data["allowed"]),
            reason=str(data["reason"]),
            payload=dict(data.get("payload", {})),
        )


class DataExport:
    """Manages GDPR-style data export requests.

    Parameters
    ----------
    subject_can_export: predicate(subject_id, scopes) -> (bool, reason).
        The caller decides whether the subject may export the requested
        scopes (e.g. after identity verification).
    data_source: provider(subject_id, scopes) -> Mapping[str, Any].
        Simulated data plane: returns the subject's data for the scopes.
    seal: optional seal function; defaults to canonical JSON (deterministic).
    audit_sink: callable receiving one dict per sealed event; must be
        provided by the caller (no default no-op).
    """

    def __init__(
        self,
        *,
        subject_can_export: Callable[[str, Tuple[str, ...]], Tuple[bool, str]],
        data_source: Callable[[str, Tuple[str, ...]], Mapping[str, Any]],
        seal: Optional[Callable[[Mapping[str, Any]], str]] = None,
        audit_sink: Callable[[Dict[str, Any]], None],
    ) -> None:
        self._subject_can_export = subject_can_export
        self._data_source = data_source
        self._seal = seal or self._default_seal
        self._audit_sink = audit_sink
        self._records: Dict[str, ExportRecord] = {}
        self._by_subject: Dict[str, set] = {}
        self._packages: Dict[str, str] = {}
        self._counter = 0

    @staticmethod
    def _default_seal(event: Mapping[str, Any]) -> str:
        return json.dumps(event, sort_keys=True, separators=(",", ":"))

    # -- internal helpers ------------------------------------------------

    def _emit(
        self, action: str, export_id: str, seq: int, extra: Mapping[str, Any]
    ) -> str:
        event = {
            "type": _EXPORT_AUDIT_TYPE,
            "action": action,
            "export_id": export_id,
            "seq": seq,
            "extra": dict(extra),
        }
        sealed = self._seal(event)
        self._audit_sink({"event": event, "sealed": sealed})
        return sealed

    def _mint_id(self, subject_id: str, seq: int) -> str:
        self._counter += 1
        return (
            f"exp-{seq}-{self._counter}-"
            f"{abs(hash((subject_id, seq, self._counter))) % 10_000_000}"
        )

    @staticmethod
    def _canonical(payload: Mapping[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _checksum(serialised: str) -> str:
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    def _serialise(self, record: ExportRecord, data: Mapping[str, Any]) -> str:
        payload = {
            "export_id": record.export_id,
            "subject_id": record.subject_id,
            "scopes": list(record.scopes),
            "generated_at_seq": record.ready_at_seq,
            "data": dict(data),
        }
        if record.format == "jsonl":
            lines = [self._canonical(payload)]
            for scope in record.scopes:
                lines.append(self._canonical({"scope": scope, "value": data.get(scope)}))
            return "\n".join(lines)
        return self._canonical(payload)

    def _replace(self, rec: ExportRecord, **changes: Any) -> ExportRecord:
        data = asdict(rec)
        data.update(changes)
        return ExportRecord(**data)

    def _lookup(self, export_id: str) -> Optional[ExportRecord]:
        return self._records.get(export_id)

    def _has_active(self, subject_id: str) -> bool:
        for eid in self._by_subject.get(subject_id, ()):
            if self._records[eid].state in ("pending", "ready"):
                return True
        return False

    # -- public API --------------------------------------------------------

    def request(self, params: ExportParams) -> Decision:
        ok, reason = params.validate()
        if not ok:
            return Decision(False, f"invalid params: {reason}")
        allowed, why = self._subject_can_export(params.subject_id, params.scopes)
        if not allowed:
            return Decision(False, f"subject not authorized: {why}")
        # fail-closed: one active export per subject at a time
        if self._has_active(params.subject_id):
            return Decision(False, "active export already exists for subject")
        export_id = self._mint_id(params.subject_id, params.requested_at_seq)
        data = self._data_source(params.subject_id, params.scopes)
        if not isinstance(data, Mapping):
            return Decision(False, "data_source returned non-mapping")
        missing = {s for s in params.scopes if s not in data}
        if missing:
            return Decision(False, f"data_source missing scopes: {sorted(missing)}")
        record = ExportRecord(
            export_id=export_id,
            subject_id=params.subject_id,
            scopes=tuple(sorted(params.scopes)),
            format=params.format,
            requested_at_seq=params.requested_at_seq,
            ready_at_seq=params.requested_at_seq,
            expires_at_seq=params.requested_at_seq + params.download_ttl_seq,
            nonce=params.nonce,
            state="ready",
        )
        serialised = self._serialise(record, data)
        record = self._replace(record, checksum=self._checksum(serialised))
        self._records[export_id] = record
        self._by_subject.setdefault(params.subject_id, set()).add(export_id)
        self._packages[export_id] = serialised
        sealed = self._emit(
            "request",
            export_id,
            params.requested_at_seq,
            {"scopes": list(record.scopes), "format": record.format},
        )
        return Decision(True, "ready", {"record": asdict(record), "sealed": sealed})

    def status(self, export_id: str, now_seq: int) -> Decision:
        if not export_id:
            return Decision(False, "export_id required")
        if now_seq < 0:
            return Decision(False, "now_seq must be non-negative")
        rec = self._lookup(export_id)
        if rec is None:
            return Decision(False, "unknown export")
        rec = self._apply_expiry(rec, now_seq)
        return Decision(True, "ok", {"record": asdict(rec)})

    def download(self, export_id: str, params: DownloadParams) -> Decision:
        ok, reason = params.validate()
        if not ok:
            return Decision(False, f"invalid params: {reason}")
        rec = self._lookup(export_id)
        if rec is None:
            return Decision(False, "unknown export")
        rec = self._apply_expiry(rec, params.now_seq)
        if rec.subject_id != params.subject_id:
            self._emit(
                "download-denied", export_id, params.now_seq, {"reason": "subject mismatch"}
            )
            return Decision(False, "subject mismatch")
        if rec.state == "expired":
            return Decision(False, "export expired")
        if rec.state == "delivered":
            return Decision(False, "export already delivered")
        if rec.state != "ready":
            return Decision(False, f"export not ready (state={rec.state})")
        serialised = self._packages.get(export_id)
        if serialised is None:
            return Decision(False, "package missing")
        if self._checksum(serialised) != rec.checksum:
            return Decision(False, "package integrity check failed")
        delivered = self._replace(rec, state="delivered")
        self._records[export_id] = delivered
        sealed = self._emit(
            "download", export_id, params.now_seq, {"checksum": rec.checksum}
        )
        return Decision(
            True,
            "delivered",
            {
                "package": serialised,
                "checksum": rec.checksum,
                "format": rec.format,
                "sealed": sealed,
                "record": asdict(delivered),
            },
        )

    # -- helpers -----------------------------------------------------------

    def _apply_expiry(self, rec: ExportRecord, now_seq: int) -> ExportRecord:
        if rec.state in ("pending", "ready") and now_seq > rec.expires_at_seq:
            expired = self._replace(rec, state="expired")
            self._records[rec.export_id] = expired
            self._emit("expire", rec.export_id, now_seq, {"reason": "ttl"})
            return expired
        return rec

    def get(self, export_id: str) -> Optional[ExportRecord]:
        return self._lookup(export_id)

    def active_for(self, subject_id: str) -> FrozenSet[ExportRecord]:
        out = {
            self._records[eid]
            for eid in self._by_subject.get(subject_id, ())
            if self._records[eid].state in ("pending", "ready")
        }
        return frozenset(out)
