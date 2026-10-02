"""File-backed evidence store: durable appends, tamper-evident reload, sealed manifests.

This is the persistence layer the in-memory :class:`EvidenceChain` deliberately
left out. One JSONL file holds one run's chain: each line is the canonical JSON
of an :class:`EvidenceEntry`, validated on every open. A store detects
modification of *its own* file; it does not stop an attacker who can replace
the whole file *and* every copy of the sealed manifest - authenticity comes
from a trusted signer's seal over the manifest, verified separately.

Honest limits, stated up front:

- **Single writer.** Concurrent writers are not coordinated; the contract is one
  process appends to a store file. POSIX ``O_APPEND`` keeps individual lines
  intact, but interleaved sequences from two writers are rejected on reload.
- **No confidentiality.** The file is plaintext JSONL. Secrets do not belong in
  evidence subjects.
- **Signatures are only as trustworthy as the key resolver.** The bundled
  :class:`HmacTestSigner` is a *test* signer: a shared-secret MAC proves nothing
  about non-repudiation, and test keys must never sign anything real. Production
  deployments inject their own :class:`SealSigner` (HSM, KMS, age, Sigstore -
  the host's choice) and resolve ``key_id`` through infrastructure they trust.
  An unknown ``key_id`` verifies as *unknown authenticity*, never as ok.
- **No trusted timestamp.** ``sealed_at`` is a caller-supplied Unix epoch; it is
  covered by the signature so it cannot be altered afterwards, but it is not an
  independent proof of *when* sealing happened.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from evidence_chain import ChainVerification, EvidenceChain, verify_chain
from evidence_contract import (
    EvidenceEntry,
    EvidenceRef,
    canonical_json,
    _digest as _check_digest,
    _identifier,
)

MANIFEST_SCHEMA_VERSION = "northstar.evidence-manifest.v1"
_SEALED_AT_MAX = (1 << 53) - 1


class SealSigner(Protocol):
    """Something the host trusts to attest to a sealed manifest's bytes."""

    @property
    def key_id(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    def sign(self, data: bytes) -> bytes: ...


class SealVerifier(Protocol):
    """The checking half of a seal; resolved from ``key_id`` by the host."""

    @property
    def key_id(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    def verify(self, data: bytes, signature: bytes) -> bool: ...


class HmacTestSigner:
    """Shared-secret HMAC signer for tests and local diagnostics only.

    A MAC authenticates to whoever holds the same secret - it is *not*
    non-repudiation, and a test key must never seal real evidence. Production
    signers are injected by the host; see the module docstring.
    """

    algorithm = "hmac-sha256-test"

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = _identifier(key_id, "key_id")
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("secret must be bytes of at least 16 bytes")
        self._secret = bytes(secret)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    def verifier(self) -> "HmacTestVerifier":
        return HmacTestVerifier(self._key_id, self._secret)


class HmacTestVerifier:
    """Checking half of :class:`HmacTestSigner`; test-only, same caveats."""

    algorithm = HmacTestSigner.algorithm

    def __init__(self, key_id: str, secret: bytes) -> None:
        self._key_id = _identifier(key_id, "key_id")
        self._secret = bytes(secret)

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(self, data: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._secret, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


def _manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """Canonical bytes covered by a seal: everything except ``signature``."""
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return canonical_json(body)


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest {field} must be a non-empty base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"manifest {field} is not valid base64") from error


@dataclass(frozen=True)
class ManifestVerification:
    """Machine-readable result of checking a sealed manifest."""

    ok: bool
    authenticity: str  # "verified" | "unknown-key" | "bad-signature" | "malformed"
    key_id: str | None
    head_digest: str | None
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "authenticity": self.authenticity,
            "key_id": self.key_id,
            "head_digest": self.head_digest,
            "errors": list(self.errors),
        }


def verify_manifest(
    manifest: Any,
    key_resolver: Mapping[str, SealVerifier],
) -> ManifestVerification:
    """Check a sealed manifest's shape and signature. Never trusts blindly.

    Unknown ``key_id`` yields ``authenticity="unknown-key"`` (``ok=False``):
    an unrecognized signer is *not* a verified seal. This function checks the
    seal over the manifest bytes only; binding the manifest to actual store
    contents (head digest, entry count) is :meth:`EvidenceStore.verify_seal`.
    """
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ManifestVerification(False, "malformed", None, None,
                                    ("manifest must be an object",))
    expected = {
        "schema_version", "run_id", "head_digest", "entry_count",
        "sealed_at", "signer", "signature",
    }
    if set(manifest) != expected:
        missing = sorted(expected - set(manifest))
        unknown = sorted(set(manifest) - expected)
        if missing:
            errors.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"unknown fields: {', '.join(unknown)}")
    head_digest = manifest.get("head_digest")
    if errors:
        return ManifestVerification(False, "malformed", None,
                                    head_digest if isinstance(head_digest, str) else None,
                                    tuple(errors))
    try:
        if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {MANIFEST_SCHEMA_VERSION}")
        _identifier(manifest["run_id"], "run_id")
        entry_count = manifest["entry_count"]
        if not isinstance(entry_count, int) or isinstance(entry_count, bool) or entry_count <= 0:
            raise ValueError("entry_count must be a positive integer")
        sealed_at = manifest["sealed_at"]
        if not isinstance(sealed_at, int) or isinstance(sealed_at, bool):
            raise ValueError("sealed_at must be an integer Unix epoch")
        if not 0 < sealed_at <= _SEALED_AT_MAX:
            raise ValueError("sealed_at is out of range")
        signer = manifest["signer"]
        if not isinstance(signer, dict) or set(signer) != {"key_id", "algorithm"}:
            raise ValueError("signer must be an object with key_id and algorithm")
        key_id = _identifier(signer["key_id"], "signer.key_id")
        if not isinstance(signer["algorithm"], str) or not signer["algorithm"]:
            raise ValueError("signer.algorithm must be a non-empty string")
        _check_digest(head_digest, "head_digest")
        signature = _b64decode(manifest["signature"], "signature")
        signed = _manifest_bytes(manifest)
    except (ValueError, TypeError, AttributeError) as error:
        return ManifestVerification(False, "malformed", None,
                                    head_digest if isinstance(head_digest, str) else None,
                                    (f"malformed manifest: {error}",))

    verifier = key_resolver.get(key_id)
    if verifier is None:
        return ManifestVerification(False, "unknown-key", key_id, head_digest,
                                    (f"key_id {key_id!r} is not trusted by this resolver",))
    try:
        valid = verifier.verify(signed, signature)
    except Exception as error:  # a hostile verifier must not crash the check
        return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                    (f"verifier raised: {error}",))
    if not valid:
        return ManifestVerification(False, "bad-signature", key_id, head_digest,
                                    ("signature does not match manifest content",))
    return ManifestVerification(True, "verified", key_id, head_digest, ())


class EvidenceStore:
    """One run's evidence chain, persisted as JSONL with a verifiable seal.

    The file is created on first append (parent directories are *not* created:
    the caller chooses where evidence lives). Every open replays and verifies
    the whole chain, so a modified file fails loudly at open time instead of
    serving tampered entries.
    """

    def __init__(self, path: str | os.PathLike[str], run_id: str) -> None:
        self._path = os.fspath(path)
        self._chain = EvidenceChain(run_id)
        self._load()

    @property
    def run_id(self) -> str:
        return self._chain.run_id

    @property
    def path(self) -> str:
        return self._path

    @property
    def entry_count(self) -> int:
        return len(self._chain.entries)

    @property
    def head_digest(self) -> str | None:
        return self._chain.head_digest

    @property
    def entries(self) -> tuple[EvidenceEntry, ...]:
        return self._chain.entries

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, "rb") as handle:
            raw = handle.read()
        if not raw.strip():
            return
        entries: list[EvidenceEntry] = []
        for lineno, line in enumerate(raw.split(b"\n"), start=1):
            if not line.strip():
                continue
            try:
                entry = EvidenceEntry.from_dict(json.loads(line))
            except Exception as error:
                raise ValueError(
                    f"evidence file {self._path!r} line {lineno} is not a valid entry: {error}"
                ) from error
            entries.append(entry)
        # Fail closed: the file must be exactly this run's intact chain.
        report = verify_chain(entries, expected_run_id=self._chain.run_id)
        if not report.ok:
            raise ValueError(
                f"evidence file {self._path!r} failed verification: "
                + "; ".join(report.errors)
            )
        for entry in entries:
            self._chain.append_entry(entry)

    def append(
        self,
        *,
        source: str,
        kind: str,
        occurred_at: int,
        subject: Mapping[str, Any] | bytes,
        refs: tuple[EvidenceRef, ...] = (),
        source_id: str | None = None,
    ) -> EvidenceEntry:
        """Validate, append to the chain, and durably write one JSONL line.

        The entry is validated *before* anything is written, so a rejected
        append never leaves a partial line. Idempotent retries via ``source_id``
        do not write a second line.
        """
        before = self.entry_count
        entry = self._chain.append(
            source=source,
            kind=kind,
            occurred_at=occurred_at,
            subject=subject,
            refs=refs,
            source_id=source_id,
        )
        if self.entry_count == before:
            return entry  # idempotent retry: already stored
        line = entry.canonical_json() + b"\n"
        with open(self._path, "ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return entry

    def verify(self) -> ChainVerification:
        """Re-verify the in-memory chain (the file was verified at open)."""
        return self._chain.verify()

    def seal(self, signer: SealSigner, *, sealed_at: int | None = None) -> dict[str, Any]:
        """Produce a sealed manifest attesting to the current chain head.

        The signature covers the canonical manifest bytes; ``signature`` itself
        is excluded from the signed input. ``sealed_at`` defaults to now (Unix
        epoch, integer). Sealing an empty chain is refused.
        """
        head = self.head_digest
        if head is None:
            raise ValueError("cannot seal an empty evidence chain")
        if sealed_at is None:
            sealed_at = int(time.time())
        if not isinstance(sealed_at, int) or isinstance(sealed_at, bool):
            raise ValueError("sealed_at must be an integer Unix epoch")
        if not 0 < sealed_at <= _SEALED_AT_MAX:
            raise ValueError("sealed_at is out of range")
        key_id = _identifier(signer.key_id, "signer.key_id")
        algorithm = signer.algorithm
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("signer.algorithm must be a non-empty string")
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "run_id": self.run_id,
            "head_digest": head,
            "entry_count": self.entry_count,
            "sealed_at": sealed_at,
            "signer": {"key_id": key_id, "algorithm": algorithm},
        }
        manifest["signature"] = _b64encode(signer.sign(_manifest_bytes(manifest)))
        return manifest

    def verify_seal(
        self,
        manifest: Mapping[str, Any],
        key_resolver: Mapping[str, SealVerifier],
    ) -> ManifestVerification:
        """Verify a seal *and* bind it to this store's current contents.

        A signature that checks out but names a different head digest or entry
        count does not describe this store, so it verifies as ``bad-signature``
        class mismatch rather than ok.
        """
        result = verify_manifest(manifest, key_resolver)
        if not result.ok:
            return result
        mismatches: list[str] = []
        if manifest.get("run_id") != self.run_id:
            mismatches.append("manifest run_id does not match this store")
        if manifest.get("head_digest") != self.head_digest:
            mismatches.append("manifest head_digest does not match this store's head")
        if manifest.get("entry_count") != self.entry_count:
            mismatches.append("manifest entry_count does not match this store")
        if mismatches:
            return ManifestVerification(False, "bad-signature", result.key_id,
                                        result.head_digest, tuple(mismatches))
        return result
