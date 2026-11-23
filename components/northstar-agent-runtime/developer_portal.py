"""Developer portal: ReadMe / Backstage-shaped API docs + console bookkeeping (simulated).

Interface:
    DeveloperPortal.docs(page_id, title, body, seq, section="")
        -> sealed DocPage (latest-wins versioning; body booked by digest only)
    DeveloperPortal.try_it(try_id, endpoint, seq, method="GET", status=200,
                           body_digest="", key_id="")
        -> sealed TryRecord (simulated "try it" console call, no network)
    DeveloperPortal.keys(key_id, seq, label="", scopes=())
        -> sealed ApiKey (key material booked by digest ref only)
    DeveloperPortal.revoke_key(key_id, seq, reason="")
        -> sealed KeyRevocation (terminal; revoked ids are never re-issued)

Developer documentation portals (ReadMe, Backstage, Stoplight) publish API
docs, offer a live "try it" console, and manage consumer API keys. This module
books those *decisions* as a deterministic single-host state machine: docs
pages are pinned by digest (markdown bytes never enter a record or cross the
audit boundary), "try it" calls are simulated host-reported outcomes (no HTTP
client, no wire truth -- a recorded 200 means the host declared success, never
that a server answered), and API key *material* never exists here: issuance
books a digest reference only. Pair with a real docs renderer, a sandboxed
console executor, and a KMS for production.

Note: the spec method ``try()`` cannot exist in Python -- ``try`` is a
reserved keyword (``def try`` is a SyntaxError). It is exposed as ``try_it``
with identical semantics.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), no wall-clock, RLock-guarded,
fail-closed, stdlib-only + standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


_MODULE_VERSION = "developer-portal.v1"
_SCHEMA_PIN = "northstar.developer-portal.v1"
_AUDIT_TYPE = "audit.ndjson/1"

# Pinned HTTP method vocabulary (what the simulated console admits).
METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

# Simulated status space: valid HTTP status codes as data, nothing dialed.
_STATUS_MIN = 100
_STATUS_MAX = 599

# Docs page caps (house discipline on host-supplied text).
_TITLE_MAX_LEN = 256
_BODY_MAX_LEN = 1 << 20  # 1 MiB
_PAGE_ID_MAX_LEN = 128
_KEY_ID_MAX_LEN = 128
_LABEL_MAX_LEN = 128
_SCOPE_MAX_LEN = 128
_MAX_SCOPES_PER_KEY = 64
_ENDPOINT_MAX_LEN = 512


class DeveloperPortalError(ValueError):
    """Base for all developer_portal errors."""


class BadDocError(DeveloperPortalError):
    """Doc page id / title / body failed validation."""


class UnknownDocError(DeveloperPortalError):
    """Doc page id not found."""


class BadTryError(DeveloperPortalError):
    """Try-it id / endpoint / method / status failed validation."""


class DuplicateTryError(DeveloperPortalError):
    """A try record with this id already exists."""


class BadKeyError(DeveloperPortalError):
    """Key id / label / scopes failed validation."""


class DuplicateKeyError(DeveloperPortalError):
    """An API key with this id already exists (revoked or active)."""


class UnknownKeyError(DeveloperPortalError):
    """API key id not found."""


class RevokedKeyError(DeveloperPortalError):
    """The API key is revoked and cannot be used."""


class AlreadyRevokedError(DeveloperPortalError):
    """The API key is already revoked."""


class BadRevocationError(DeveloperPortalError):
    """Revocation reason failed validation."""


class SeqOrderError(DeveloperPortalError):
    """Caller seq did not strictly increase."""


def _reject(reason: str) -> DeveloperPortalError:
    table = {
        "bad-doc": BadDocError,
        "unknown-doc": UnknownDocError,
        "bad-try": BadTryError,
        "duplicate-try": DuplicateTryError,
        "duplicate-try": DuplicateTryError,
        "bad-key": BadKeyError,
        "duplicate-key": DuplicateKeyError,
        "unknown-key": UnknownKeyError,
        "revoked-key": RevokedKeyError,
        "already-revoked": AlreadyRevokedError,
        "bad-revocation": BadRevocationError,
        "seq": SeqOrderError,
    }
    return table.get(reason, DeveloperPortalError)(reason)


def _check_seq_kind(seq: Any) -> None:
    # bool is an int subclass; reject it explicitly (house discipline).
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise _reject("seq")


def _check_str(value: Any, name: str, max_len: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise DeveloperPortalError(f"{name} must be a string")
    if not allow_empty and not value:
        raise DeveloperPortalError(f"{name} must be non-empty")
    if len(value) > max_len:
        raise DeveloperPortalError(f"{name} exceeds {max_len} chars")
    return value


def _digest(kind: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(jcs_canonical_json(payload))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Sealed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DocPage:
    """One pinned docs page version (frozen). Body booked by digest only."""

    page_id: str
    title: str
    section: str
    body_digest: str
    version: int
    supersedes: str  # "" for v1; otherwise the superseded page digest
    seq: int
    digest: str

    def verify_digest(self) -> bool:
        return self.digest == _digest(
            "doc-page",
            {
                "page_id": self.page_id,
                "title": self.title,
                "section": self.section,
                "body_digest": self.body_digest,
                "version": self.version,
                "supersedes": self.supersedes,
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class TryRecord:
    """One simulated 'try it' console call (frozen). Outcome is host-reported data."""

    try_id: str
    endpoint: str
    method: str
    status: int
    body_digest: str
    key_id: str  # "" when the call carried no key
    seq: int
    digest: str

    def verify_digest(self) -> bool:
        return self.digest == _digest(
            "try-record",
            {
                "try_id": self.try_id,
                "endpoint": self.endpoint,
                "method": self.method,
                "status": self.status,
                "body_digest": self.body_digest,
                "key_id": self.key_id,
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class ApiKey:
    """One issued API key (frozen). Material never exists here; ref is a digest."""

    key_id: str
    label: str
    scopes: Tuple[str, ...]
    key_ref: str  # "sha256:..." reference, never key material
    revoked: bool  # mirrored at issue time; revocations book separately
    seq: int
    digest: str

    def verify_digest(self) -> bool:
        return self.digest == _digest(
            "api-key",
            {
                "key_id": self.key_id,
                "label": self.label,
                "scopes": list(self.scopes),
                "key_ref": self.key_ref,
                "revoked": self.revoked,
                "seq": self.seq,
            },
        )


@dataclass(frozen=True)
class KeyRevocation:
    """One terminal API key revocation (frozen)."""

    key_id: str
    reason: str
    seq: int
    digest: str

    def verify_digest(self) -> bool:
        return self.digest == _digest(
            "key-revocation",
            {"key_id": self.key_id, "reason": self.reason, "seq": self.seq},
        )


# ---------------------------------------------------------------------------
# The portal
# ---------------------------------------------------------------------------


class DeveloperPortal:
    """Deterministic developer-portal bookkeeping (ReadMe / Backstage shape).

    Docs publishing, simulated "try it" console calls, and API key lifecycle
    as fail-closed single-host bookkeeping. All mutations take a
    caller-supplied strictly-increasing int ``seq``; failed mutations consume
    their seq. Markdown bodies and key material never enter records and never
    cross the audit boundary.
    """

    def __init__(self, audit: Any = None) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._docs: Dict[str, DocPage] = {}
        self._tries: Dict[str, TryRecord] = {}
        self._keys: Dict[str, ApiKey] = {}
        self._revocations: Dict[str, KeyRevocation] = {}
        self._audit: List[Dict[str, Any]] = [] if audit is None else audit

    # -- internal helpers ----------------------------------------------------

    def _require_seq(self, seq: int) -> None:
        _check_seq_kind(seq)
        if seq <= self._seq:
            raise _reject("seq")
        self._seq = seq

    def _emit(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        record = {
            "schema_version": _AUDIT_TYPE,
            "component": "northstar-agent-runtime",
            "module": _MODULE_VERSION,
            "event": kind,
            "seq": seq,
            "detail": detail,
        }
        if hasattr(self._audit, "append"):
            self._audit.append(record)
        else:  # pragma: no cover - defensive
            self._audit(record)

    def _fail_locked(self, reason: str, seq: int, why: str = "") -> DeveloperPortalError:
        # Failed mutations consume their seq (batch discipline).
        self._require_seq(seq)
        self._emit("docs-portal.rejected", seq, {"reason": reason, "why": why})
        return _reject(reason)

    @staticmethod
    def _pin(kind: str, rec: Any) -> Any:
        payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
        return type(rec)(**{**payload, "digest": _digest(kind, payload)})

    # -- docs ----------------------------------------------------------------

    def docs(
        self,
        page_id: Any,
        title: Any,
        body: Any,
        seq: int,
        section: Any = "",
    ) -> DocPage:
        """Publish (or re-publish) a docs page; re-publish mints a new version.

        ``body`` is pinned by digest -- markdown bytes never enter the record.
        """
        with self._lock:
            try:
                page_id = _check_str(page_id, "page_id", _PAGE_ID_MAX_LEN)
                title = _check_str(title, "title", _TITLE_MAX_LEN)
                if not isinstance(body, str) or not body:
                    raise BadDocError("body must be a non-empty string")
                if len(body) > _BODY_MAX_LEN:
                    raise BadDocError("body exceeds 1 MiB")
                section = _check_str(section, "section", _TITLE_MAX_LEN, allow_empty=True)
            except DeveloperPortalError as exc:
                raise self._fail_locked("bad-doc", seq, str(exc))
            self._require_seq(seq)
            body_digest = _digest("doc-body", {"page_id": page_id, "body": body})
            prev = self._docs.get(page_id)
            version = 1 if prev is None else prev.version + 1
            supersedes = "" if prev is None else prev.digest
            rec = self._pin(
                "doc-page",
                DocPage(
                    page_id=page_id,
                    title=title,
                    section=section,
                    body_digest=body_digest,
                    version=version,
                    supersedes=supersedes,
                    seq=seq,
                    digest="",
                ),
            )
            self._docs[page_id] = rec
            self._emit(
                "docs-portal.page-published",
                seq,
                {
                    "page_id": page_id,
                    "version": version,
                    "body_digest": body_digest,
                    "supersedes": supersedes,
                },
            )
            return rec

    # -- try it ---------------------------------------------------------------

    def try_it(
        self,
        try_id: Any,
        endpoint: Any,
        seq: int,
        method: str = "GET",
        status: int = 200,
        body_digest: Any = "",
        key_id: Any = "",
    ) -> TryRecord:
        """Book one simulated 'try it' console call (no network).

        ``status``/``body_digest`` are host-reported outcomes booked as data.
        A recorded 200 means the host declared success, never that a server
        answered. ``key_id`` is validated when given; revoked keys are refused.
        """
        with self._lock:
            try:
                try_id = _check_str(try_id, "try_id", _PAGE_ID_MAX_LEN)
                endpoint = _check_str(endpoint, "endpoint", _ENDPOINT_MAX_LEN)
                if method not in METHODS:
                    raise BadTryError(f"method must be one of {METHODS}")
                if isinstance(status, bool) or not isinstance(status, int):
                    raise BadTryError("status must be an int")
                if not (_STATUS_MIN <= status <= _STATUS_MAX):
                    raise BadTryError("status must be a valid HTTP status code")
                if not isinstance(body_digest, str):
                    raise BadTryError("body_digest must be a string")
                if len(body_digest) > 256:
                    raise BadTryError("body_digest exceeds 256 chars")
                key_id = _check_str(key_id, "key_id", _KEY_ID_MAX_LEN, allow_empty=True)
                if try_id in self._tries:
                    raise DuplicateTryError(f"try_id already booked: {try_id!r}")
                if key_id:
                    key = self._keys.get(key_id)
                    if key is None:
                        raise UnknownKeyError(f"unknown key_id: {key_id!r}")
                    if key.key_id in self._revocations:
                        raise RevokedKeyError(f"key revoked: {key_id!r}")
            except DeveloperPortalError as exc:
                raise self._fail_locked(
                    {
                        BadTryError: "bad-try",
                        DuplicateTryError: "duplicate-try",
                        UnknownKeyError: "unknown-key",
                        RevokedKeyError: "revoked-key",
                    }.get(type(exc), "bad-try"),
                    seq,
                    str(exc),
                )
            self._require_seq(seq)
            rec = self._pin(
                "try-record",
                TryRecord(
                    try_id=try_id,
                    endpoint=endpoint,
                    method=method,
                    status=status,
                    body_digest=body_digest,
                    key_id=key_id,
                    seq=seq,
                    digest="",
                ),
            )
            self._tries[try_id] = rec
            self._emit(
                "docs-portal.try-recorded",
                seq,
                {"try_id": try_id, "endpoint": endpoint, "status": status},
            )
            return rec

    # -- keys ------------------------------------------------------------------

    def keys(
        self,
        key_id: Any,
        seq: int,
        label: Any = "",
        scopes: Any = (),
    ) -> ApiKey:
        """Issue an API key. Key material never exists here -- only a digest ref.

        Revoked ids are retired and never re-issued.
        """
        with self._lock:
            try:
                key_id = _check_str(key_id, "key_id", _KEY_ID_MAX_LEN)
                label = _check_str(label, "label", _LABEL_MAX_LEN, allow_empty=True)
                if not isinstance(scopes, (tuple, list)):
                    raise BadKeyError("scopes must be a tuple/list of strings")
                scopes = tuple(scopes)
                if len(scopes) > _MAX_SCOPES_PER_KEY:
                    raise BadKeyError("too many scopes")
                for scope in scopes:
                    _check_str(scope, "scope", _SCOPE_MAX_LEN)
                if key_id in self._keys:
                    raise DuplicateKeyError(f"key_id already issued: {key_id!r}")
            except DeveloperPortalError as exc:
                raise self._fail_locked(
                    "duplicate-key" if isinstance(exc, DuplicateKeyError) else "bad-key",
                    seq,
                    str(exc),
                )
            self._require_seq(seq)
            key_ref = _digest("key-material", {"key_id": key_id, "seq": seq})
            rec = self._pin(
                "api-key",
                ApiKey(
                    key_id=key_id,
                    label=label,
                    scopes=scopes,
                    key_ref=key_ref,
                    revoked=False,
                    seq=seq,
                    digest="",
                ),
            )
            self._keys[key_id] = rec
            self._emit(
                "docs-portal.key-issued",
                seq,
                {"key_id": key_id, "scopes": list(scopes), "key_ref": key_ref},
            )
            return rec

    def revoke_key(self, key_id: Any, seq: int, reason: Any = "") -> KeyRevocation:
        """Revoke an API key (terminal; the id is retired and never re-issued)."""
        with self._lock:
            try:
                key_id = _check_str(key_id, "key_id", _KEY_ID_MAX_LEN)
                reason = _check_str(reason, "reason", _LABEL_MAX_LEN, allow_empty=True)
                key = self._keys.get(key_id)
                if key is None:
                    raise UnknownKeyError(f"unknown key_id: {key_id!r}")
                if key_id in self._revocations:
                    raise AlreadyRevokedError(f"key already revoked: {key_id!r}")
            except DeveloperPortalError as exc:
                raise self._fail_locked(
                    {
                        UnknownKeyError: "unknown-key",
                        AlreadyRevokedError: "already-revoked",
                    }.get(type(exc), "bad-revocation"),
                    seq,
                    str(exc),
                )
            self._require_seq(seq)
            rec = self._pin(
                "key-revocation",
                KeyRevocation(key_id=key_id, reason=reason, seq=seq, digest=""),
            )
            self._revocations[key_id] = rec
            self._keys[key_id] = self._pin(
                "api-key", type(key)(**{**asdict(key), "revoked": True, "digest": ""})
            )
            self._emit("docs-portal.key-revoked", seq, {"key_id": key_id})
            return rec

    # -- views -----------------------------------------------------------------

    def page(self, page_id: str) -> DocPage:
        with self._lock:
            rec = self._docs.get(page_id)
            if rec is None:
                raise _reject("unknown-doc")
            return rec

    def try_record(self, try_id: str) -> TryRecord:
        with self._lock:
            rec = self._tries.get(try_id)
            if rec is None:
                raise _reject("bad-try")
            return rec

    def key(self, key_id: str) -> ApiKey:
        with self._lock:
            rec = self._keys.get(key_id)
            if rec is None:
                raise _reject("unknown-key")
            return rec

    def page_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._docs)

    def key_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._keys)

    def active_key_ids(self) -> List[str]:
        with self._lock:
            return sorted(k for k in self._keys if k not in self._revocations)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "pages": len(self._docs),
                "tries": len(self._tries),
                "keys": len(self._keys),
                "revoked_keys": len(self._revocations),
                "seq": self._seq,
            }

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "pages": {k: asdict(v) for k, v in self._docs.items()},
                "tries": {k: asdict(v) for k, v in self._tries.items()},
                "keys": {k: asdict(v) for k, v in self._keys.items()},
                "revocations": {k: asdict(v) for k, v in self._revocations.items()},
                "seq": self._seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def developer_portal_audit_event(
    kind: str, detail: Dict[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the developer-portal module."""
    _kinds = (
        "docs-portal.page-published",
        "docs-portal.try-recorded",
        "docs-portal.key-issued",
        "docs-portal.key-revoked",
        "docs-portal.rejected",
    )
    if kind not in _kinds:
        raise DeveloperPortalError(f"unknown audit kind: {kind!r}")
    _check_seq_kind(seq)
    if not isinstance(detail, dict):
        raise DeveloperPortalError("detail must be a dict")
    # Doc bodies and key material never cross the audit boundary; digests only.
    banned = {"body", "key_material", "secret", "token", "private_key"}
    if any(k in detail for k in banned):
        raise DeveloperPortalError("detail carries banned keys")
    return {
        "schema_version": _AUDIT_TYPE,
        "component": "northstar-agent-runtime",
        "module": _MODULE_VERSION,
        "schema": _SCHEMA_PIN,
        "event": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def main() -> int:
    events: List[Dict[str, Any]] = []
    dp = DeveloperPortal(audit=events.append)
    p = dp.docs("getting-started", "Getting Started", "# Hello\n", 1, section="guides")
    assert p.verify_digest() and p.version == 1 and p.supersedes == ""
    p2 = dp.docs("getting-started", "Getting Started", "# Hello v2\n", 2)
    assert p2.verify_digest() and p2.version == 2 and p2.supersedes == p.digest
    k = dp.keys("k-1", 3, label="ci", scopes=("read", "write"))
    assert k.verify_digest() and not k.revoked
    t = dp.try_it("t-1", "/v1/users", 4, method="GET", status=200, key_id="k-1")
    assert t.verify_digest()
    r = dp.revoke_key("k-1", 5, reason="rotation")
    assert r.verify_digest()
    assert dp.key("k-1").revoked
    try:
        dp.try_it("t-2", "/v1/users", 6, key_id="k-1")
    except RevokedKeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("revoked key must refuse try_it")
    print("developer-portal OK: docs, versions, try_it, keys, revoke, pins")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
