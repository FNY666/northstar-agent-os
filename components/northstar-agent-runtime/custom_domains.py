"""Custom domains: map / verify / ssl (simulated domain mapping interface).

Interface:
    CustomDomains.map(domain, subject_id, seq) -> sealed MappingRecord (pending)
    CustomDomains.verify(mapping_id, seq)      -> sealed VerificationRecord
    CustomDomains.ssl(mapping_id, seq)         -> sealed SSLRecord

DNS reality is outside this module: the caller injects a ``verifier``
callable ``verify(domain) -> bool`` that represents "the host observed
proof of domain control". A raising verifier is treated as denial
(fail-closed). Certificates are simulated records pinned by digest;
no real CA interaction happens. No wall-clock: the caller supplies a
monotonic ``seq``. Validation is fail-closed: malformed domains,
duplicate live mappings, verification of unknown mappings, and SSL
issuance for unverified mappings are all denied and audited.

House style: frozen dataclasses, stdlib only, audit events as
``audit.ndjson/1`` JSONL lines supplied by the caller.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Tuple


_MODULE_VERSION = "custom-domains.v1"
_SCHEMA_PIN = "northstar.custom-domains.v1"
_AUDIT_TYPE = "audit.ndjson/1"

_SSL_VALIDITY_SEQ = 10_000  # logical-seq window a cert stays valid
_MAX_LABEL = 63
_MAX_DOMAIN = 253

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class CustomDomainError(ValueError):
    """Base for all custom_domains errors."""


class BadDomainError(CustomDomainError):
    """Domain name failed validation."""


class DuplicateMappingError(CustomDomainError):
    """A live mapping already exists for the domain."""


class UnknownMappingError(CustomDomainError):
    """Mapping id not found."""


class AlreadyVerifiedError(CustomDomainError):
    """Mapping is already verified."""


class VerificationDeniedError(CustomDomainError):
    """Domain-control proof not observed (fail-closed)."""


class NotVerifiedError(CustomDomainError):
    """Operation requires a verified mapping."""


class SeqOrderError(CustomDomainError):
    """Caller seq did not strictly increase."""


def _domain_error(reason: str) -> CustomDomainError:
    table = {
        "duplicate": DuplicateMappingError,
        "unknown": UnknownMappingError,
        "bad-domain": BadDomainError,
        "already-verified": AlreadyVerifiedError,
        "denied": VerificationDeniedError,
        "not-verified": NotVerifiedError,
        "seq": SeqOrderError,
    }
    return table.get(reason, CustomDomainError)(reason)


def validate_domain(domain: Any) -> Tuple[bool, str]:
    """Structural domain validation (no DNS involved)."""
    if not isinstance(domain, str):
        return False, "domain must be str"
    d = domain.strip().lower()
    if not d or len(d) > _MAX_DOMAIN:
        return False, "domain length out of range"
    if d.startswith(".") or d.endswith(".") or ".." in d:
        return False, "malformed domain"
    labels = d.split(".")
    if len(labels) < 2:
        return False, "needs at least two labels"
    for lab in labels:
        if not _LABEL_RE.match(lab):
            return False, f"bad label: {lab!r}"
    return True, ""


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _digest(kind: str, payload: Mapping[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(_canonical(payload).encode("utf-8"))
    return "sha256:" + h.hexdigest()


@dataclass(frozen=True)
class MappingRecord:
    mapping_id: str
    domain: str
    subject_id: str
    state: str  # "pending" | "verified"
    created_at_seq: int
    verified_at_seq: Optional[int] = None
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("mapping", payload)


@dataclass(frozen=True)
class VerificationRecord:
    verification_id: str
    mapping_id: str
    domain: str
    ok: bool
    checked_at_seq: int
    detail: str = ""
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("verification", payload)


@dataclass(frozen=True)
class SSLRecord:
    cert_id: str
    mapping_id: str
    domain: str
    issued_at_seq: int
    expires_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("ssl", payload)

    def valid_at(self, seq: int) -> bool:
        return self.issued_at_seq <= seq < self.expires_at_seq


class CustomDomains:
    """Simulated custom-domain mapping bookkeeping.

    Args:
        verifier: ``(domain) -> bool``; True when the host observed
            proof of domain control. A raising verifier counts as False.
        audit: caller-supplied ``(event_dict) -> None`` sink for
            ``audit.ndjson/1`` events.
    """

    def __init__(
        self,
        verifier: Callable[[str], bool],
        audit: Callable[[Dict[str, Any]], None],
    ) -> None:
        if not callable(verifier):
            raise CustomDomainError("verifier must be callable")
        if not callable(audit):
            raise CustomDomainError("audit must be callable")
        self._verifier = verifier
        self._audit = audit
        self._lock = threading.RLock()
        self._seq = 0
        self._counter = 0
        self._v_counter = 0
        self._c_counter = 0
        self._mappings: Dict[str, MappingRecord] = {}
        self._by_domain: Dict[str, str] = {}  # domain -> live mapping_id

    # -- public API ----------------------------------------------------------

    def map(self, domain: Any, subject_id: str, seq: int) -> MappingRecord:
        with self._lock:
            self._require_seq(seq)
            ok, why = validate_domain(domain)
            if not ok:
                raise self._reject("bad-domain", seq, why)
            if not isinstance(subject_id, str) or not subject_id.strip():
                raise self._reject("bad-subject", seq, "subject_id required")
            d = str(domain).strip().lower()
            existing = self._by_domain.get(d)
            if existing is not None:
                raise self._reject("duplicate", seq, f"domain already mapped: {existing}")
            self._counter += 1
            mid = f"map-{self._counter}"
            payload = {
                "mapping_id": mid,
                "domain": d,
                "subject_id": subject_id.strip(),
                "state": "pending",
                "created_at_seq": seq,
                "verified_at_seq": None,
            }
            rec = MappingRecord(digest=_digest("mapping", payload), **payload)
            self._mappings[mid] = rec
            self._by_domain[d] = mid
            self._emit("mapped", seq, {"mapping_id": mid, "domain": d})
            return rec

    def verify(self, mapping_id: str, seq: int) -> VerificationRecord:
        with self._lock:
            self._require_seq(seq)
            rec = self._mappings.get(mapping_id)
            if rec is None:
                raise self._reject("unknown", seq, f"unknown mapping: {mapping_id!r}")
            if rec.state == "verified":
                raise self._reject("already-verified", seq, mapping_id)
            try:
                ok = bool(self._verifier(rec.domain))
            except Exception:
                ok = False
            self._v_counter += 1
            vid = f"ver-{self._v_counter}"
            payload = {
                "verification_id": vid,
                "mapping_id": mapping_id,
                "domain": rec.domain,
                "ok": ok,
                "checked_at_seq": seq,
                "detail": "domain-control observed" if ok else "domain-control not observed",
            }
            vrec = VerificationRecord(digest=_digest("verification", payload), **payload)
            if ok:
                updated = MappingRecord(
                    mapping_id=rec.mapping_id,
                    domain=rec.domain,
                    subject_id=rec.subject_id,
                    state="verified",
                    created_at_seq=rec.created_at_seq,
                    verified_at_seq=seq,
                    digest="",
                )
                upd_payload = {k: v for k, v in asdict(updated).items() if k != "digest"}
                updated = MappingRecord(
                    digest=_digest("mapping", upd_payload), **upd_payload
                )
                self._mappings[mapping_id] = updated
                self._emit("verified", seq, {"mapping_id": mapping_id})
            else:
                self._emit("verify-denied", seq, {"mapping_id": mapping_id})
            return vrec

    def ssl(self, mapping_id: str, seq: int) -> SSLRecord:
        with self._lock:
            self._require_seq(seq)
            rec = self._mappings.get(mapping_id)
            if rec is None:
                raise self._reject("unknown", seq, f"unknown mapping: {mapping_id!r}")
            if rec.state != "verified":
                raise self._reject("not-verified", seq, mapping_id)
            self._c_counter += 1
            cid = f"cert-{self._c_counter}"
            payload = {
                "cert_id": cid,
                "mapping_id": mapping_id,
                "domain": rec.domain,
                "issued_at_seq": seq,
                "expires_at_seq": seq + _SSL_VALIDITY_SEQ,
            }
            cert = SSLRecord(digest=_digest("ssl", payload), **payload)
            self._emit("ssl-issued", seq, {"cert_id": cid, "mapping_id": mapping_id})
            return cert

    # -- views ---------------------------------------------------------------

    def get(self, mapping_id: str) -> Optional[MappingRecord]:
        with self._lock:
            return self._mappings.get(mapping_id)

    def mapping_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._mappings))

    def mapping_for(self, domain: str) -> Optional[MappingRecord]:
        with self._lock:
            mid = self._by_domain.get(str(domain).strip().lower())
            return self._mappings.get(mid) if mid else None

    # -- internals -------------------------------------------------------------

    def _require_seq(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise self._reject("seq", seq, "seq must be a positive int")
        if seq <= self._seq:
            raise SeqOrderError(f"seq must strictly increase: {seq} <= {self._seq}")
        self._seq = seq

    def _reject(self, reason: str, seq: int, detail: str) -> CustomDomainError:
        self._emit("rejected", seq, {"reason": reason, "detail": detail})
        return _domain_error(reason)

    def _emit(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        event = {
            "type": _AUDIT_TYPE,
            "module": _MODULE_VERSION,
            "schema": _SCHEMA_PIN,
            "kind": kind,
            "seq": seq,
            "detail": dict(detail),
        }
        self._audit(event)


def custom_domains_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    return {
        "type": _AUDIT_TYPE,
        "module": _MODULE_VERSION,
        "schema": _SCHEMA_PIN,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail or {}),
    }


def main() -> None:
    events = []
    cd = CustomDomains(lambda d: d == "app.example.com", events.append)
    m = cd.map("app.example.com", "tenant-1", 1)
    assert m.verify_digest()
    v = cd.verify(m.mapping_id, 2)
    assert v.ok and v.verify_digest()
    c = cd.ssl(m.mapping_id, 3)
    assert c.valid_at(3) and not c.valid_at(3 + _SSL_VALIDITY_SEQ)
    print("custom-domains OK: map, verify, ssl, pins")


if __name__ == "__main__":
    main()
