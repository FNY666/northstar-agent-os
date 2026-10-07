"""C2PA (Coalition for Content Provenance and Authenticity) decision ledger, simulated.

Research motivation: C2PA content credentials attach a signed manifest of
assertions to an asset -- what made it, what ingredients went in, what
actions transformed it. The failure modes are bookkeeping failures:
manifests bound to the wrong asset digest, duplicate assertion labels,
signature claims that cannot be re-derived, and verdicts that pretend
to be cryptographic proofs.

This module is the *decision ledger* half of that shape:

- ``C2PA.manifest(manifest_id, asset_digest, seq, generator="")`` --
  declare one C2PA manifest pinned to an asset's ``sha256:`` digest.
  Asset bytes never enter a record -- the digest pin only. Returns a
  frozen ``ManifestRecord`` with a ``sha256:`` digest pin. Duplicate
  ids are refused fail-closed; ids are never recycled.
- ``C2PA.assertion(manifest_id, assertion_id, kind, seq,
  content_digest="")`` -- book one assertion on the manifest under a
  pinned assertion-kind vocabulary (``assert`` is a reserved word, so
  the spec's ``assert`` maps to this method). Assertion content travels
  as a digest pin only -- raw assertions never enter records. Returns
  a frozen ``AssertionRecord`` with a minted-less, caller-named
  ``assertion_id``; duplicate ids per manifest are refused.
- ``C2PA.verify(manifest_id, seq)`` -- pure read view: re-walks every
  digest pin in the manifest, checks structural invariants (at least
  one assertion, every assertion carries a well-formed content pin),
  and books nothing. Integrity is returned as data (``ok`` bool),
  never raised. Returns a frozen ``VerifyReport`` with a digest pin.
- ``c2pa_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``manifest-declared`` / ``asserted`` / ``rejected``);
  caller-supplied seqs only. Raw asset bytes, assertion content, and
  signatures never cross the audit boundary -- audit rows carry ids,
  counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``manifest_id`` / ``assertion_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``asset_digest`` must be a ``sha256:``-prefixed digest pin.
- ``kind`` must name the pinned assertion-kind vocabulary.
- ``content_digest`` must be a ``sha256:``-prefixed pin when supplied.
- Asserting against an unknown manifest raises ``UnknownManifestError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* manifests and *host-reported* digest
  pins. A booked manifest is a ledger entry, not a signed credential
  -- the module runs no X.509 validation, checks no trust list, and
  cannot prove the host controls the pinned asset.
- ``verify()`` re-derives digest pins and structural invariants only;
  ``ok=True`` means "the ledger's pins are self-consistent", never
  "the asset's provenance is authentic".
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if provenance state must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj):  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj):  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
C2PA_VERSION = "c2pa.v1"

#: Schema pin carried by records and audit events.
C2PA_SCHEMA = "northstar.c2pa.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned C2PA assertion-kind vocabulary (curie-shaped, short form).
KIND_CREATIVE_WORK = "creative-work"
KIND_ACTION = "action"
KIND_INGREDIENT = "ingredient"
KIND_HASH_DATA = "hash-data"
KIND_THUMBNAIL = "thumbnail"
KIND_SIGNATURE = "signature"
KIND_PHOTO_METADATA = "photo-metadata"
ASSERTION_KINDS = (KIND_CREATIVE_WORK, KIND_ACTION, KIND_INGREDIENT,
                   KIND_HASH_DATA, KIND_THUMBNAIL, KIND_SIGNATURE,
                   KIND_PHOTO_METADATA)

#: Audit event kinds.
KIND_MANIFEST_DECLARED = "manifest-declared"
KIND_ASSERTED = "asserted"
KIND_REJECTED = "rejected"
_KINDS = (KIND_MANIFEST_DECLARED, KIND_ASSERTED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"asset", "content", "payload", "value", "raw", "text", "data",
     "signature", "bytes"})

#: Max id length.
_MAX_ID_LEN = 256

#: Digest prefix.
_DIGEST_PREFIX = "sha256:"


class C2PAError(Exception):
    """Base error for the C2PA ledger (programming errors)."""


class BadManifestError(C2PAError):
    """Raised when a manifest id is malformed."""


class DuplicateManifestError(C2PAError):
    """Raised when a manifest id is declared twice."""


class UnknownManifestError(C2PAError):
    """Raised when a manifest id names no declared manifest."""


class BadAssetError(C2PAError):
    """Raised when an asset digest pin is malformed."""


class BadKindError(C2PAError):
    """Raised when an assertion kind is outside the pinned vocabulary."""


class DuplicateAssertionError(C2PAError):
    """Raised when an assertion id is booked twice on a manifest."""


class BadAssertionError(C2PAError):
    """Raised when an assertion id is malformed."""


class BadDigestError(C2PAError):
    """Raised when a content digest pin is malformed."""


class SeqOrderError(C2PAError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(C2PAError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value, name="seq"):
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value, name):
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadManifestError(
            f"{name} must be str, got {type(value).__name__}")
    if not value:
        raise BadManifestError(f"{name} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadManifestError(f"{name} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadManifestError(f"{name} must not contain whitespace")
    return value


def _check_manifest_id(manifest_id):
    return _check_id(manifest_id, "manifest_id")


def _check_assertion_id(assertion_id):
    try:
        return _check_id(assertion_id, "assertion_id")
    except BadManifestError as e:
        raise BadAssertionError(str(e))


def _check_digest(digest, name, error_cls):
    """Validate a digest pin: 'sha256:'-prefixed, non-empty body."""
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise error_cls(f"{name} must be str, got {type(digest).__name__}")
    if not digest.startswith(_DIGEST_PREFIX) or \
            len(digest) <= len(_DIGEST_PREFIX):
        raise error_cls(f"{name} must be a sha256:-prefixed digest pin")
    return digest


def _check_asset_digest(digest):
    return _check_digest(digest, "asset_digest", BadAssetError)


def _check_content_digest(digest):
    if not digest:
        return ""
    return _check_digest(digest, "content_digest", BadDigestError)


def _check_kind(kind):
    """Validate an assertion kind against the pinned vocabulary."""
    if kind not in ASSERTION_KINDS:
        raise BadKindError(
            f"kind must be one of {list(ASSERTION_KINDS)}, got {kind!r}")
    return kind


def _check_generator(generator):
    if isinstance(generator, bool) or not isinstance(generator, str):
        raise BadManifestError(
            f"generator must be str, got {type(generator).__name__}")
    if len(generator) > _MAX_ID_LEN:
        raise BadManifestError(f"generator too long (>{_MAX_ID_LEN} chars)")
    return generator


def _pin(*parts):
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": C2PA_SCHEMA,
        "parts": list(parts),
    })


def c2pa_audit_event(kind, detail, seq):
    """Build one ``audit.ndjson/1`` audit row for the C2PA ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": C2PA_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ManifestRecord:
    """Frozen record of a declared C2PA manifest."""
    manifest_id: str
    asset_digest: str
    generator: str
    seq: int
    digest: str

    def verify(self, asset_digest, generator):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("manifest", self.manifest_id,
                                   asset_digest, generator, self.seq)


@dataclass(frozen=True)
class AssertionRecord:
    """Frozen record of one booked assertion on a manifest."""
    assertion_id: str
    manifest_id: str
    kind: str
    content_digest: str
    seq: int
    digest: str

    def verify(self, manifest_id, kind, content_digest):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("assertion", self.assertion_id,
                                   manifest_id, kind, content_digest,
                                   self.seq)


@dataclass(frozen=True)
class VerifyReport:
    """Pure read view: digest re-derivation + structural checks as data."""
    manifest_id: str
    seq: int
    # Recomputed pins over (manifest, assertions); True = self-consistent.
    pins_ok: bool
    # Structural invariant: at least one assertion booked.
    has_assertions: bool
    # Structural invariant: every booked assertion carries a content pin.
    all_pinned: bool
    assertion_count: int
    digest: str

    def verify(self, pins_ok, has_assertions, all_pinned, assertion_count):
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verify", self.manifest_id, pins_ok, has_assertions,
            all_pinned, assertion_count, self.seq)


class C2PA:
    """Deterministic C2PA manifest/assertion decision ledger (simulated).

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._manifests: Dict[str, ManifestRecord] = {}
        self._assertions: Dict[str, AssertionRecord] = {}
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq):
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq, error):
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(c2pa_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, audit_kind, detail, seq):
        self._audit.append(c2pa_audit_event(audit_kind, detail, seq))

    # -- mutations ----------------------------------------------------------

    def manifest(self, manifest_id, asset_digest, seq, generator=""):
        """Declare a C2PA manifest pinned to an asset digest."""
        with self._lock:
            seq = self._claim(seq)
            try:
                manifest_id = _check_manifest_id(manifest_id)
                asset_digest = _check_asset_digest(asset_digest)
                generator = _check_generator(generator)
                if manifest_id in self._manifests:
                    raise DuplicateManifestError(
                        f"manifest already declared: {manifest_id!r}")
            except C2PAError as e:
                self._burn(seq, e)
            rec = ManifestRecord(manifest_id=manifest_id,
                                 asset_digest=asset_digest,
                                 generator=generator, seq=seq,
                                 digest=_pin("manifest", manifest_id,
                                             asset_digest, generator, seq))
            self._manifests[manifest_id] = rec
            self._last_seq = seq
            self._emit(KIND_MANIFEST_DECLARED,
                       {"manifest_id": manifest_id,
                        "asset_digest": asset_digest,
                        "digest": rec.digest}, seq)
            return rec

    def assertion(self, manifest_id, assertion_id, kind, seq,
                  content_digest=""):
        """Book one assertion on a declared manifest (spec's ``assert``)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                manifest_id = _check_manifest_id(manifest_id)
                assertion_id = _check_assertion_id(assertion_id)
                kind = _check_kind(kind)
                content_digest = _check_content_digest(content_digest)
                if manifest_id not in self._manifests:
                    raise UnknownManifestError(
                        f"unknown manifest: {manifest_id!r}")
                key = (manifest_id, assertion_id)
                if key in self._assertions:
                    raise DuplicateAssertionError(
                        f"assertion already booked: {assertion_id!r} "
                        f"on {manifest_id!r}")
            except C2PAError as e:
                self._burn(seq, e)
            rec = AssertionRecord(assertion_id=assertion_id,
                                  manifest_id=manifest_id, kind=kind,
                                  content_digest=content_digest, seq=seq,
                                  digest=_pin("assertion", assertion_id,
                                              manifest_id, kind,
                                              content_digest, seq))
            self._assertions[(manifest_id, assertion_id)] = rec
            self._last_seq = seq
            self._emit(KIND_ASSERTED,
                       {"manifest_id": manifest_id,
                        "assertion_id": assertion_id, "kind": kind,
                        "digest": rec.digest}, seq)
            return rec

    # -- views ---------------------------------------------------------------

    def verify(self, manifest_id, seq):
        """Pure read: re-derive pins + structural checks (no audit row)."""
        _check_seq(seq)
        with self._lock:
            man = self._manifests.get(_check_manifest_id(manifest_id))
            if man is None:
                raise UnknownManifestError(
                    f"unknown manifest: {manifest_id!r}")
            assertions = [r for (m, _), r in self._assertions.items()
                          if m == manifest_id]
            pins_ok = man.verify(man.asset_digest, man.generator) and \
                all(r.verify(r.manifest_id, r.kind, r.content_digest)
                    for r in assertions)
            has_assertions = len(assertions) > 0
            all_pinned = all(bool(r.content_digest) for r in assertions)
            digest = _pin("verify", manifest_id, pins_ok, has_assertions,
                          all_pinned, len(assertions), seq)
            return VerifyReport(manifest_id=manifest_id, seq=seq,
                                pins_ok=pins_ok,
                                has_assertions=has_assertions,
                                all_pinned=all_pinned,
                                assertion_count=len(assertions),
                                digest=digest)

    def manifest_record(self, manifest_id):
        """Return the manifest record, or None when unknown (pure read)."""
        return self._manifests.get(manifest_id)

    def manifest_ids(self):
        """Sorted declared manifest ids (pure read)."""
        return tuple(sorted(self._manifests))

    def assertion_record(self, manifest_id, assertion_id):
        """Return the assertion record, or None when unknown (pure read)."""
        return self._assertions.get((manifest_id, assertion_id))

    def assertion_ids(self, manifest_id):
        """Sorted booked assertion ids for a manifest (pure read)."""
        return tuple(sorted(a for (m, a) in self._assertions
                            if m == manifest_id))

    def audit_log(self):
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main():
    """Self-check: manifest, assertion, verify."""
    c = C2PA()
    asset = "sha256:" + "a" * 64
    m = c.manifest("man-001", asset, 1, generator="agent-v1")
    assert m.verify(asset, "agent-v1")
    cd = "sha256:" + "b" * 64
    r1 = c.assertion("man-001", "a-001", "ingredient", 2,
                     content_digest=cd)
    assert r1.verify("man-001", "ingredient", cd)
    r2 = c.assertion("man-001", "a-002", "action", 3, content_digest=cd)
    assert r2.verify("man-001", "action", cd)
    rep = c.verify("man-001", 3)
    assert rep.pins_ok and rep.has_assertions and rep.all_pinned
    assert rep.assertion_count == 2
    assert rep.verify(True, True, True, 2)
    assert len(c.audit_log()) == 3
    print("c2pa OK: manifest, assertion, verify, pins, audit")


if __name__ == "__main__":
    main()
