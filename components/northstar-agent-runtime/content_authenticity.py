"""content_authenticity.py — content-authenticity signature bookkeeping.

C2PA / content-credentials-shaped signing as a deterministic single-host
state machine: register issuers, book host-declared signature bindings,
verify content digests against the ledger, and revoke signatures. Simulated:
the ledger performs no cryptographic verification of its own — the
host declares the signature binding, the module only books, pins, and
compares digests (the GIGO boundary shared with every other bookkeeping
module in this repo). A ``VerifyReport`` with verdict ``authentic`` means
the ledger's booked pins agree, never that the content is genuinely
authentic or that a signature was truly made by the named issuer.

Scope discipline shared with the rest of the repo:
- frozen dataclasses; caller-supplied strictly increasing int seqs
  (failed mutations consume their seq, rewinds raise bare without
  consuming anything);
- no wall-clock anywhere;
- RLock-guarded;
- fail-closed error taxonomy;
- stdlib-only (``canonical_json`` try/except fallback);
- ``sha256:`` digest pins over JCS-canonical form with ``verify()``;
- ``audit.ndjson/1`` events; raw content, keys, and reasons never cross
  the audit boundary.
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

VERSION = "content-authenticity.v1"
SCHEMA = "northstar.content-authenticity.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_INT = 2 ** 53
_MAX_ID_LEN = 128

# Verdict vocabulary for verify(): booked as data, never a finding of fact.
VERDICTS = (
    "authentic",
    "mismatch",
    "revoked",
    "unsigned",
)

# Pinned revocation reasons; the raw reason text never enters a record.
REASONS = (
    "manual",
    "key-compromised",
    "issuer-withdrawn",
    "content-recalled",
    "superseded",
)

AUDIT_KINDS = (
    "issuer-registered",
    "content-signed",
    "signature-revoked",
    "content-authenticity.rejected",
)


class ContentAuthenticityError(Exception):
    """Base for all content-authenticity errors."""


class BadIdError(ContentAuthenticityError):
    pass


class DuplicateIssuerError(ContentAuthenticityError):
    pass


class UnknownIssuerError(ContentAuthenticityError):
    pass


class DuplicateContentError(ContentAuthenticityError):
    pass


class UnknownContentError(ContentAuthenticityError):
    pass


class UnknownSignatureError(ContentAuthenticityError):
    pass


class AlreadyRevokedError(ContentAuthenticityError):
    pass


class BadDigestError(ContentAuthenticityError):
    pass


class BadReasonError(ContentAuthenticityError):
    pass


class SeqOrderError(ContentAuthenticityError):
    pass


class AuditKindError(ContentAuthenticityError):
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


def _check_digest(value: Any, what: str) -> str:
    """Content/issuer/key material travels as ``sha256:`` pins only."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) != len(_DIGEST_PREFIX) + 64:
        raise BadDigestError(
            f"{what} must be a {(_DIGEST_PREFIX + '<64hex>')!r} digest pin"
        )
    try:
        int(value[len(_DIGEST_PREFIX):], 16)
    except ValueError:
        raise BadDigestError(f"{what} digest pin is not hex") from None
    return value


def _check_reason(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReasonError(f"reason must be a str, got {type(value).__name__}")
    if value not in REASONS:
        raise BadReasonError(f"reason {value!r} not in pinned vocabulary")
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
                raise ContentAuthenticityError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ContentAuthenticityError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ContentAuthenticityError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def _pin_text(text: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IssuerRecord:
    """One booked issuer registration. The public key travels as a digest pin only."""

    issuer_id: str
    key_digest: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "issuer_id": self.issuer_id,
            "key_digest": self.key_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin((self.issuer_id, self.key_digest), "issuer")
        return self.digest == expect


@dataclass(frozen=True)
class SignatureRecord:
    """One booked signature binding. Books the declaration, not the crypto."""

    signature_id: str
    content_id: str
    content_digest: str
    issuer_id: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "content_id": self.content_id,
            "content_digest": self.content_digest,
            "issuer_id": self.issuer_id,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.signature_id, self.content_id, self.content_digest, self.issuer_id),
            "signature",
        )
        return self.digest == expect


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal revocation of one signature id; never recycled."""

    signature_id: str
    reason: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "reason": self.reason,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin((self.signature_id, self.reason), "revocation")
        return self.digest == expect


@dataclass(frozen=True)
class VerifyReport:
    """Pure-read verdict over the ledger pins; verdict is data, never proof."""

    content_id: str
    content_digest: str
    verdict: str
    matched_signature_id: str
    digest: str
    seq: int
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "content_digest": self.content_digest,
            "verdict": self.verdict,
            "matched_signature_id": self.matched_signature_id,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.content_id,
                self.content_digest,
                self.verdict,
                self.matched_signature_id,
            ),
            "verify-report",
        )
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def content_authenticity_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw content/keys never cross this boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "content",
        "text",
        "payload",
        "raw",
        "body",
        "value",
        "key",
        "private_key",
        "public_key",
        "reason",
        "message",
        "signature",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "content-authenticity",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Content-authenticity ledger
# ---------------------------------------------------------------------------


class ContentAuthenticity:
    """Content-authenticity signature bookkeeping: sign, verify, revoke."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # issuer_id -> IssuerRecord (insertion ordered)
        self._issuers: Dict[str, IssuerRecord] = {}
        # signature_id -> SignatureRecord (insertion ordered)
        self._signatures: Dict[str, SignatureRecord] = {}
        # content_id -> list of signature ids, in booking order
        self._content_signatures: Dict[str, List[str]] = {}
        # signature_id -> RevocationRecord
        self._revocations: Dict[str, RevocationRecord] = {}
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
            content_authenticity_audit_event(audit_kind, seq, **detail)
        )

    def _fail(
        self, seq: int, exc: ContentAuthenticityError, **detail: Any
    ) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def register_issuer(
        self, issuer_id: str, seq: int, key_digest: str = ""
    ) -> IssuerRecord:
        """Declare one trusted issuer. The public key travels as a digest pin only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                issuer_id = _check_id(issuer_id, "issuer_id")
                if issuer_id in self._issuers:
                    raise DuplicateIssuerError(f"issuer {issuer_id!r} already registered")
                if key_digest:
                    key_digest = _check_digest(key_digest, "key_digest")
            except ContentAuthenticityError as exc:
                self._fail(seq, exc, issuer_id=str(issuer_id))
            record = IssuerRecord(
                issuer_id=issuer_id,
                key_digest=key_digest,
                digest=_digest_pin((issuer_id, key_digest), "issuer"),
                seq=seq,
            )
            self._issuers[issuer_id] = record
            self._emit("issuer-registered", seq, issuer_id=issuer_id)
            return record

    def sign(
        self, content_id: str, content_digest: str, issuer_id: str, seq: int
    ) -> SignatureRecord:
        """Book one host-declared signature binding. Books the declaration, not the crypto."""
        with self._lock:
            seq = self._claim(seq)
            try:
                content_id = _check_id(content_id, "content_id")
                content_digest = _check_digest(content_digest, "content_digest")
                issuer_id = _check_id(issuer_id, "issuer_id")
                if issuer_id not in self._issuers:
                    raise UnknownIssuerError(f"issuer {issuer_id!r} not registered")
            except ContentAuthenticityError as exc:
                self._fail(seq, exc, content_id=str(content_id))
            signature_id = f"sig-{len(self._signatures) + 1}"
            record = SignatureRecord(
                signature_id=signature_id,
                content_id=content_id,
                content_digest=content_digest,
                issuer_id=issuer_id,
                digest=_digest_pin(
                    (signature_id, content_id, content_digest, issuer_id), "signature"
                ),
                seq=seq,
            )
            self._signatures[signature_id] = record
            self._content_signatures.setdefault(content_id, []).append(signature_id)
            self._emit(
                "content-signed",
                seq,
                signature_id=signature_id,
                content_id=content_id,
                issuer_id=issuer_id,
            )
            return record

    def verify(self, content_id: str, content_digest: str, seq: int) -> VerifyReport:
        """Pure read: compare the ledger's latest live pin against the presented one.

        Verdict is data — ``authentic`` means the booked pins agree, never that
        the content is genuinely authentic.
        """
        _check_seq(seq)
        content_id = _check_id(content_id, "content_id")
        content_digest = _check_digest(content_digest, "content_digest")
        sig_ids = self._content_signatures.get(content_id, [])
        live = [s for s in sig_ids if s not in self._revocations]
        if not sig_ids:
            verdict, matched = "unsigned", ""
        elif not live:
            verdict, matched = "revoked", sig_ids[-1]
        else:
            latest = self._signatures[live[-1]]
            if latest.content_digest == content_digest:
                verdict, matched = "authentic", latest.signature_id
            else:
                verdict, matched = "mismatch", latest.signature_id
        return VerifyReport(
            content_id=content_id,
            content_digest=content_digest,
            verdict=verdict,
            matched_signature_id=matched,
            digest=_digest_pin(
                (content_id, content_digest, verdict, matched), "verify-report"
            ),
            seq=seq,
        )

    def revoke(
        self, signature_id: str, seq: int, reason: str = "manual"
    ) -> RevocationRecord:
        """Terminally revoke one signature id. Revoked signatures never match again."""
        with self._lock:
            seq = self._claim(seq)
            try:
                signature_id = _check_id(signature_id, "signature_id")
                reason = _check_reason(reason)
                if signature_id not in self._signatures:
                    raise UnknownSignatureError(
                        f"signature {signature_id!r} not booked"
                    )
                if signature_id in self._revocations:
                    raise AlreadyRevokedError(
                        f"signature {signature_id!r} already revoked"
                    )
            except ContentAuthenticityError as exc:
                self._fail(seq, exc, signature_id=str(signature_id))
            record = RevocationRecord(
                signature_id=signature_id,
                reason=reason,
                digest=_digest_pin((signature_id, reason), "revocation"),
                seq=seq,
            )
            self._revocations[signature_id] = record
            self._emit("signature-revoked", seq, signature_id=signature_id)
            return record

    # -- views (pure reads: validate seq shape, never consume, no audit rows) --

    def issuer_record(self, issuer_id: str, seq: int) -> IssuerRecord:
        _check_seq(seq)
        _check_id(issuer_id, "issuer_id")
        if issuer_id not in self._issuers:
            raise UnknownIssuerError(f"issuer {issuer_id!r} not registered")
        return self._issuers[issuer_id]

    def issuer_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(self._issuers)

    def signature_record(self, signature_id: str, seq: int) -> SignatureRecord:
        _check_seq(seq)
        _check_id(signature_id, "signature_id")
        if signature_id not in self._signatures:
            raise UnknownSignatureError(f"signature {signature_id!r} not booked")
        return self._signatures[signature_id]

    def signatures_for(self, content_id: str, seq: int) -> Tuple[SignatureRecord, ...]:
        _check_seq(seq)
        _check_id(content_id, "content_id")
        if content_id not in self._content_signatures:
            raise UnknownContentError(f"content {content_id!r} has no signatures")
        return tuple(
            self._signatures[s] for s in self._content_signatures[content_id]
        )

    def revocation_record(self, signature_id: str, seq: int) -> RevocationRecord:
        _check_seq(seq)
        _check_id(signature_id, "signature_id")
        if signature_id not in self._revocations:
            raise UnknownSignatureError(f"signature {signature_id!r} not revoked")
        return self._revocations[signature_id]

    def revoked_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        return tuple(sorted(self._revocations))

    def stats(self, seq: int) -> Dict[str, int]:
        _check_seq(seq)
        return {
            "issuers": len(self._issuers),
            "signatures": len(self._signatures),
            "revocations": len(self._revocations),
            "contents": len(self._content_signatures),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    ca = ContentAuthenticity()
    key_pin = _pin_text("issuer public key bytes")
    rec = ca.register_issuer("newsroom", 1, key_digest=key_pin)
    assert rec.verify() and rec.issuer_id == "newsroom"
    assert rec.key_digest == key_pin
    try:
        ca.register_issuer("newsroom", 2)
    except DuplicateIssuerError:
        pass
    else:
        raise AssertionError("duplicate issuer accepted")
    content_pin = _pin_text("the article body")
    sig = ca.sign("article-1", content_pin, "newsroom", 3)
    assert sig.verify() and sig.signature_id == "sig-1"
    report = ca.verify("article-1", content_pin, 4)
    assert report.verify() and report.verdict == "authentic"
    assert report.matched_signature_id == "sig-1"
    other_pin = _pin_text("tampered body")
    report2 = ca.verify("article-1", other_pin, 4)
    assert report2.verdict == "mismatch"
    report3 = ca.verify("never-signed", content_pin, 4)
    assert report3.verdict == "unsigned"
    rev = ca.revoke("sig-1", 5, reason="key-compromised")
    assert rev.verify() and rev.reason == "key-compromised"
    report4 = ca.verify("article-1", content_pin, 6)
    assert report4.verdict == "revoked"
    try:
        ca.revoke("sig-1", 7)
    except AlreadyRevokedError:
        pass
    else:
        raise AssertionError("double revoke accepted")
    try:
        ca.sign("article-2", content_pin, "no-such-issuer", 8)
    except UnknownIssuerError:
        pass
    else:
        raise AssertionError("unknown issuer sign accepted")
    try:
        ca.sign("article-2", "raw-content", "newsroom", 9)
    except BadDigestError:
        pass
    else:
        raise AssertionError("raw content sign accepted")
    assert ca.stats(10)["signatures"] == 1
    assert ca.revoked_ids(10) == ("sig-1",)
    rows = ca.audit_log(10)
    # 3 success rows + 4 rejected rows (dup issuer, double revoke,
    # unknown issuer, raw content)
    assert len(rows) == 7
    assert sum(1 for r in rows if r["kind"] == "content-authenticity.rejected") == 4
    ca2 = ContentAuthenticity()
    ca2.register_issuer("b", 1)
    ca2.register_issuer("a", 2)
    assert ca2.issuer_ids(3) == ("b", "a")
    print("content-authenticity OK: sign, verify, revoke, pins, audit")


if __name__ == "__main__":
    main()
