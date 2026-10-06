"""Signed, policy-aware receipt for a completed run evidence snapshot.

This module deliberately reuses the host-injected ``SealSigner`` and
``SealVerifier`` protocols from :mod:`evidence_store`. It does not create,
load, or persist production keys. Receipt signatures use a distinct domain
separator so a signature from another Northstar object type cannot be replayed
as a run receipt.

A receipt signs claims about completion and capture policy together with a
summary of one validated evidence-chain snapshot. Verification without the
matching ledger can check the signature but reports integrity as ``unknown``;
verification against an :class:`EvidenceStore` also binds the receipt to the
actual chain and completion evidence entry. A trusted signer attests to the
completion/verifier fields; a signature is not a trusted timestamp or proof
that an untrusted verifier ran honestly.
"""
from __future__ import annotations

import base64
import binascii
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from evidence_chain import verify_chain
from evidence_contract import EvidenceEntry, canonical_json
from evidence_store import EvidenceStore, SealSigner, SealVerifier

SEALED_RUN_RECEIPT_SCHEMA_VERSION = "northstar.sealed-run-receipt.v1"
_RECEIPT_DOMAIN = b"northstar.sealed-run-receipt.v1\0"
_MAX_SAFE_INTEGER = (1 << 53) - 1
_MAX_RECEIPT_SOURCES = 256
_MAX_SIGNATURE_BYTES = 16 * 1024
_MAX_RECEIPT_JSON_BYTES = 256 * 1024
_IDENTIFIER_RE = re.compile(r"^[^\s/\\\x00-\x1f\x7f]+$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_STATUSES = frozenset({"finished", "failed", "cancelled"})
_VERIFIER_VERDICTS = frozenset({"passed", "failed", "not-run", "unknown"})


def _identifier(
    value: Any,
    field: str,
    *,
    max_chars: int = 128,
    ascii_only: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_chars
        or (ascii_only and not value.isascii())
        or not _IDENTIFIER_RE.fullmatch(value)
        or value in {".", ".."}
    ):
        raise ValueError(f"{field} must be a safe non-empty identifier")
    return value


def _label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase source label")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _positive_epoch(value: Any, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
        or value > _MAX_SAFE_INTEGER
    ):
        raise ValueError(f"{field} must be a positive interoperable Unix epoch")
    return value


def _exact_fields(value: Any, expected: set[str], field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown fields: {', '.join(unknown)}")
        raise ValueError(f"{field} " + "; ".join(details))
    return value


def _sorted_labels(values: Any, field: str, *, non_empty: bool) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"{field} must be a list")
    if len(values) > _MAX_RECEIPT_SOURCES:
        raise ValueError(f"{field} has too many source labels")
    normalized = tuple(_label(item, f"{field}[{index}]") for index, item in enumerate(values))
    if non_empty and not normalized:
        raise ValueError(f"{field} must not be empty")
    if normalized != tuple(sorted(set(normalized))):
        raise ValueError(f"{field} must be sorted and contain no duplicates")
    return normalized


def _signature_input(body: Mapping[str, Any]) -> bytes:
    encoded = canonical_json(body)
    if len(encoded) > _MAX_RECEIPT_JSON_BYTES:
        raise ValueError("canonical sealed run receipt exceeds the size limit")
    return _RECEIPT_DOMAIN + encoded


def _encode_signature(signature: bytes) -> str:
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("signer.sign() must return non-empty bytes")
    if len(signature) > _MAX_SIGNATURE_BYTES:
        raise ValueError("signer signature exceeds the receipt size limit")
    return base64.b64encode(signature).decode("ascii")


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("signature must be a non-empty base64 string")
    if len(value) > ((_MAX_SIGNATURE_BYTES + 2) // 3) * 4:
        raise ValueError("signature exceeds the receipt size limit")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as error:
        raise ValueError("signature is not valid base64") from error
    if not raw:
        raise ValueError("signature must not decode to empty bytes")
    if len(raw) > _MAX_SIGNATURE_BYTES:
        raise ValueError("signature exceeds the receipt size limit")
    return raw


@dataclass(frozen=True)
class CompletionEvidence:
    """Explicit terminal outcome claim anchored to one ledger entry."""

    status: str
    completed_at: int
    evidence_entry_digest: str
    verifier_verdict: str
    test_exit_code: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.status, str) or self.status not in _TERMINAL_STATUSES:
            raise ValueError("completion.status must be finished, failed, or cancelled")
        _positive_epoch(self.completed_at, "completion.completed_at")
        _digest(self.evidence_entry_digest, "completion.evidence_entry_digest")
        if (
            not isinstance(self.verifier_verdict, str)
            or self.verifier_verdict not in _VERIFIER_VERDICTS
        ):
            raise ValueError("completion.verifier_verdict is invalid")
        code = self.test_exit_code
        if code is not None and (
            not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255
        ):
            raise ValueError("completion.test_exit_code must be null or an integer from 0 to 255")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "completed_at": self.completed_at,
            "evidence_entry_digest": self.evidence_entry_digest,
            "verifier_verdict": self.verifier_verdict,
            "test_exit_code": self.test_exit_code,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "CompletionEvidence":
        data = _exact_fields(
            value,
            {"status", "completed_at", "evidence_entry_digest", "verifier_verdict", "test_exit_code"},
            "completion",
        )
        return cls(
            status=data["status"],
            completed_at=data["completed_at"],
            evidence_entry_digest=data["evidence_entry_digest"],
            verifier_verdict=data["verifier_verdict"],
            test_exit_code=data["test_exit_code"],
        )


@dataclass(frozen=True)
class SourceRoot:
    """Per-source tail and count derived from the signed ledger snapshot."""

    source: str
    entry_count: int
    head_digest: str

    def __post_init__(self) -> None:
        _label(self.source, "source_root.source")
        if (
            not isinstance(self.entry_count, int)
            or isinstance(self.entry_count, bool)
            or self.entry_count <= 0
            or self.entry_count > _MAX_SAFE_INTEGER
        ):
            raise ValueError("source_root.entry_count must be a positive integer")
        _digest(self.head_digest, "source_root.head_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "entry_count": self.entry_count,
            "head_digest": self.head_digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SourceRoot":
        data = _exact_fields(value, {"source", "entry_count", "head_digest"}, "source_root")
        return cls(
            source=data["source"],
            entry_count=data["entry_count"],
            head_digest=data["head_digest"],
        )


def _source_roots(entries: tuple[EvidenceEntry, ...]) -> tuple[SourceRoot, ...]:
    counts: dict[str, int] = {}
    tails: dict[str, str] = {}
    for entry in entries:
        counts[entry.source] = counts.get(entry.source, 0) + 1
        tails[entry.source] = entry.entry_digest
    return tuple(
        SourceRoot(source, counts[source], tails[source])
        for source in sorted(counts)
    )


@dataclass(frozen=True)
class SealedRunReceipt:
    """Immutable signed summary of one complete, validated evidence snapshot."""

    schema_version: str
    run_id: str
    sealed_at: int
    completion: CompletionEvidence
    capture_policy_revision: str | None
    capture_policy_digest: str | None
    entry_count: int
    first_entry_digest: str
    head_digest: str
    source_roots: tuple[SourceRoot, ...]
    required_sources: tuple[str, ...]
    observed_sources: tuple[str, ...]
    signer_key_id: str
    signer_algorithm: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != SEALED_RUN_RECEIPT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SEALED_RUN_RECEIPT_SCHEMA_VERSION}")
        _identifier(self.run_id, "run_id")
        _positive_epoch(self.sealed_at, "sealed_at")
        if self.capture_policy_revision is not None:
            _identifier(self.capture_policy_revision, "capture_policy.revision")
        if self.capture_policy_digest is not None:
            _digest(self.capture_policy_digest, "capture_policy.digest")
        if (
            not isinstance(self.entry_count, int)
            or isinstance(self.entry_count, bool)
            or self.entry_count <= 0
            or self.entry_count > _MAX_SAFE_INTEGER
        ):
            raise ValueError("ledger.entry_count must be a positive integer")
        _digest(self.first_entry_digest, "ledger.first_entry_digest")
        _digest(self.head_digest, "ledger.head_digest")
        if not isinstance(self.source_roots, tuple) or not self.source_roots:
            raise ValueError("ledger.source_roots must be a non-empty tuple")
        if len(self.source_roots) > _MAX_RECEIPT_SOURCES:
            raise ValueError("ledger.source_roots has too many source labels")
        if not all(isinstance(root, SourceRoot) for root in self.source_roots):
            raise ValueError("ledger.source_roots must contain SourceRoot values")
        sources = tuple(root.source for root in self.source_roots)
        if sources != tuple(sorted(set(sources))):
            raise ValueError("ledger.source_roots must be sorted and unique")
        if sum(root.entry_count for root in self.source_roots) != self.entry_count:
            raise ValueError("ledger.source_roots counts do not equal ledger.entry_count")
        if self.head_digest not in {root.head_digest for root in self.source_roots}:
            raise ValueError("ledger.head_digest must match a per-source tail digest")
        if not isinstance(self.required_sources, tuple) or not isinstance(
            self.observed_sources, tuple
        ):
            raise ValueError("required_sources and observed_sources must be immutable tuples")
        required = _sorted_labels(self.required_sources, "required_sources", non_empty=True)
        observed = _sorted_labels(self.observed_sources, "observed_sources", non_empty=True)
        if observed != sources:
            raise ValueError("observed_sources must exactly match ledger.source_roots")
        if not isinstance(self.completion, CompletionEvidence):
            raise ValueError("completion must be CompletionEvidence")
        _identifier(self.signer_key_id, "signer.key_id", ascii_only=True)
        _identifier(self.signer_algorithm, "signer.algorithm", ascii_only=True)
        _decode_signature(self.signature)

    @property
    def missing_sources(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.required_sources) - set(self.observed_sources)))

    def body_dict(self) -> dict[str, Any]:
        """Canonical signed fields; the signature never signs itself."""
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "sealed_at": self.sealed_at,
            "completion": self.completion.to_dict(),
            "capture_policy": {
                "revision": self.capture_policy_revision,
                "digest": self.capture_policy_digest,
            },
            "ledger": {
                "entry_count": self.entry_count,
                "first_entry_digest": self.first_entry_digest,
                "head_digest": self.head_digest,
                "source_roots": [root.to_dict() for root in self.source_roots],
            },
            "required_sources": list(self.required_sources),
            "observed_sources": list(self.observed_sources),
            "missing_sources": list(self.missing_sources),
            "signer": {"key_id": self.signer_key_id, "algorithm": self.signer_algorithm},
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body_dict(), "signature": self.signature}

    def canonical_json(self) -> bytes:
        """Serialize the complete signed receipt as canonical UTF-8 JSON."""
        encoded = canonical_json(self.to_dict())
        if len(encoded) > _MAX_RECEIPT_JSON_BYTES:
            raise ValueError("sealed run receipt exceeds the size limit")
        return encoded

    @classmethod
    def from_dict(cls, value: Any) -> "SealedRunReceipt":
        data = _exact_fields(
            value,
            {
                "schema_version", "run_id", "sealed_at", "completion", "capture_policy",
                "ledger", "required_sources", "observed_sources", "missing_sources",
                "signer", "signature",
            },
            "sealed run receipt",
        )
        policy = _exact_fields(data["capture_policy"], {"revision", "digest"}, "capture_policy")
        ledger = _exact_fields(
            data["ledger"],
            {"entry_count", "first_entry_digest", "head_digest", "source_roots"},
            "ledger",
        )
        signer = _exact_fields(data["signer"], {"key_id", "algorithm"}, "signer")
        raw_roots = ledger["source_roots"]
        if not isinstance(raw_roots, list):
            raise ValueError("ledger.source_roots must be a list")
        if len(raw_roots) > _MAX_RECEIPT_SOURCES:
            raise ValueError("ledger.source_roots has too many source labels")
        roots = tuple(SourceRoot.from_dict(root) for root in raw_roots)
        required = _sorted_labels(data["required_sources"], "required_sources", non_empty=True)
        observed = _sorted_labels(data["observed_sources"], "observed_sources", non_empty=True)
        missing = _sorted_labels(data["missing_sources"], "missing_sources", non_empty=False)
        expected_missing = tuple(sorted(set(required) - set(observed)))
        if missing != expected_missing:
            raise ValueError("missing_sources does not match required_sources and observed_sources")
        return cls(
            schema_version=data["schema_version"],
            run_id=data["run_id"],
            sealed_at=data["sealed_at"],
            completion=CompletionEvidence.from_dict(data["completion"]),
            capture_policy_revision=policy["revision"],
            capture_policy_digest=policy["digest"],
            entry_count=ledger["entry_count"],
            first_entry_digest=ledger["first_entry_digest"],
            head_digest=ledger["head_digest"],
            source_roots=roots,
            required_sources=required,
            observed_sources=observed,
            signer_key_id=signer["key_id"],
            signer_algorithm=signer["algorithm"],
            signature=data["signature"],
        )


@dataclass(frozen=True)
class RunReceiptVerification:
    """Layered verification result; only ``run_verdict=verified`` is success."""

    integrity: Literal["verified", "failed", "unknown"]
    completeness: Literal["complete", "incomplete"]
    authenticity: Literal["verified", "unknown-key", "bad-signature", "malformed"]
    run_verdict: Literal["verified", "failed", "unknown"]
    run_id: str | None
    key_id: str | None
    errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.run_verdict == "verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "integrity": self.integrity,
            "completeness": self.completeness,
            "authenticity": self.authenticity,
            "run_verdict": self.run_verdict,
            "run_id": self.run_id,
            "key_id": self.key_id,
            "errors": list(self.errors),
        }


def seal_run_receipt(
    store: EvidenceStore,
    *,
    completion: CompletionEvidence,
    required_sources: Iterable[str],
    signer: SealSigner,
    capture_policy_revision: str | None = None,
    capture_policy_digest: str | None = None,
    sealed_at: int | None = None,
) -> SealedRunReceipt:
    """Sign a complete receipt bound to one validated ledger snapshot.

    ``completion.evidence_entry_digest`` must identify an entry in this chain.
    Every requested source must already be represented in the ledger. Incomplete
    capture is rejected rather than signed as a complete receipt.
    """
    if not isinstance(store, EvidenceStore):
        raise ValueError("store must be an EvidenceStore")
    if not isinstance(completion, CompletionEvidence):
        raise ValueError("completion must be CompletionEvidence")
    if isinstance(required_sources, (str, bytes)):
        raise ValueError("required_sources must be an iterable of source labels")
    try:
        required_set: set[str] = set()
        for index, item in enumerate(required_sources):
            if index >= _MAX_RECEIPT_SOURCES:
                raise ValueError("required_sources has too many source labels")
            required_set.add(_label(item, "required_sources item"))
        required = tuple(sorted(required_set))
    except TypeError as error:
        raise ValueError("required_sources must be iterable") from error
    if not required:
        raise ValueError("required_sources must not be empty")
    if capture_policy_revision is not None:
        _identifier(capture_policy_revision, "capture_policy.revision")
    if capture_policy_digest is not None:
        _digest(capture_policy_digest, "capture_policy.digest")
    if sealed_at is None:
        sealed_at = int(time.time())
    _positive_epoch(sealed_at, "sealed_at")
    key_id = _identifier(signer.key_id, "signer.key_id", ascii_only=True)
    algorithm = _identifier(signer.algorithm, "signer.algorithm", ascii_only=True)

    # load() returns one validated immutable tuple; the receipt intentionally
    # binds that snapshot even if another append occurs after this call.
    entries = store.load()
    if not entries:
        raise ValueError("cannot seal a receipt for an empty evidence chain")
    if not verify_chain(entries, expected_run_id=store.run_id).ok:
        raise ValueError("evidence chain failed verification")
    entry_digests = {entry.entry_digest for entry in entries}
    if completion.evidence_entry_digest not in entry_digests:
        raise ValueError("completion evidence entry is not present in this ledger snapshot")

    roots = _source_roots(entries)
    if len(roots) > _MAX_RECEIPT_SOURCES:
        raise ValueError("evidence ledger contains too many distinct sources for a receipt")
    observed = tuple(root.source for root in roots)
    missing = tuple(sorted(set(required) - set(observed)))
    if missing:
        raise ValueError(f"cannot seal an incomplete receipt; missing sources: {', '.join(missing)}")

    body: dict[str, Any] = {
        "schema_version": SEALED_RUN_RECEIPT_SCHEMA_VERSION,
        "run_id": store.run_id,
        "sealed_at": sealed_at,
        "completion": completion.to_dict(),
        "capture_policy": {
            "revision": capture_policy_revision,
            "digest": capture_policy_digest,
        },
        "ledger": {
            "entry_count": len(entries),
            "first_entry_digest": entries[0].entry_digest,
            "head_digest": entries[-1].entry_digest,
            "source_roots": [root.to_dict() for root in roots],
        },
        "required_sources": list(required),
        "observed_sources": list(observed),
        "missing_sources": list(missing),
        "signer": {"key_id": key_id, "algorithm": algorithm},
    }
    # Parse once before signing so signer and verifier use exactly the same
    # normalized body, including derived fields such as missing_sources.
    unsigned = SealedRunReceipt.from_dict({**body, "signature": "AA=="})
    signature = _encode_signature(signer.sign(_signature_input(unsigned.body_dict())))
    return SealedRunReceipt.from_dict({**unsigned.body_dict(), "signature": signature})


def _receipt_authenticity(
    receipt: SealedRunReceipt,
    key_resolver: Mapping[str, SealVerifier],
    errors: list[str],
) -> Literal["verified", "unknown-key", "bad-signature"]:
    try:
        verifier = key_resolver.get(receipt.signer_key_id)
    except Exception:
        errors.append("trusted key resolver raised an exception")
        return "unknown-key"
    if verifier is None:
        errors.append(f"key_id {receipt.signer_key_id!r} is not trusted by this resolver")
        return "unknown-key"
    try:
        raw_verifier_key_id = verifier.key_id
        raw_verifier_algorithm = verifier.algorithm
        if type(raw_verifier_key_id) is not str or type(raw_verifier_algorithm) is not str:
            errors.append("resolved verifier identity fields must be strings")
            return "bad-signature"
        verifier_key_id = _identifier(
            raw_verifier_key_id, "resolved verifier.key_id", ascii_only=True
        )
        verifier_algorithm = _identifier(
            raw_verifier_algorithm, "resolved verifier.algorithm", ascii_only=True
        )
        if verifier_key_id != receipt.signer_key_id:
            errors.append("resolved verifier key_id does not match signer.key_id")
            return "bad-signature"
        if verifier_algorithm != receipt.signer_algorithm:
            errors.append("resolved verifier algorithm does not match signer.algorithm")
            return "bad-signature"
        signature = _decode_signature(receipt.signature)
        valid = verifier.verify(_signature_input(receipt.body_dict()), signature)
        if valid is not True:
            errors.append("signature does not match sealed run receipt content")
            return "bad-signature"
    except Exception as error:  # verifier implementations are external/untrusted code
        error_type = type(error).__name__
        errors.append(f"receipt verifier raised {error_type[:64]}")
        return "bad-signature"
    return "verified"


def verify_run_receipt(
    receipt: SealedRunReceipt | Mapping[str, Any],
    key_resolver: Mapping[str, SealVerifier],
    *,
    store: EvidenceStore | None = None,
    expected_run_id: str | None = None,
) -> RunReceiptVerification:
    """Verify receipt shape/signature and optionally bind it to a ledger.

    Without ``store``, integrity is ``unknown``: the signed summary has not been
    compared with the underlying chain. Unknown keys are never treated as
    authenticated. A successful run verdict additionally requires a finished
    run, a passing independent verifier, complete required sources, and a
    ledger snapshot that exactly matches the signed roots.
    """
    try:
        if type(receipt) is SealedRunReceipt:
            parsed = SealedRunReceipt.from_dict(receipt.to_dict())
        else:
            parsed = SealedRunReceipt.from_dict(receipt)
    except (ValueError, TypeError, AttributeError, RecursionError) as error:
        return RunReceiptVerification(
            "failed", "incomplete", "malformed", "failed", None, None,
            (f"malformed sealed run receipt: {error}",),
        )

    errors: list[str] = []
    completeness: Literal["complete", "incomplete"] = (
        "complete" if not parsed.missing_sources else "incomplete"
    )
    if isinstance(key_resolver, Mapping):
        authenticity = _receipt_authenticity(parsed, key_resolver, errors)
    else:
        errors.append("key_resolver must be a mapping of key IDs to trusted verifiers")
        authenticity = "unknown-key"
    integrity: Literal["verified", "failed", "unknown"] = "unknown"
    expected_identity_mismatch = (
        expected_run_id is not None and parsed.run_id != expected_run_id
    )

    if expected_identity_mismatch:
        errors.append("receipt run_id does not match expected_run_id")
        integrity = "failed"
    if store is not None:
        if not isinstance(store, EvidenceStore):
            errors.append("store must be an EvidenceStore")
            integrity = "failed"
        elif parsed.run_id != store.run_id:
            errors.append("receipt run_id does not match evidence store")
            integrity = "failed"
        else:
            try:
                entries = store.load()
                chain_report = verify_chain(entries, expected_run_id=parsed.run_id)
                actual_roots = _source_roots(entries) if entries else ()
                actual = (
                    len(entries),
                    entries[0].entry_digest if entries else None,
                    entries[-1].entry_digest if entries else None,
                    actual_roots,
                    parsed.completion.evidence_entry_digest in {entry.entry_digest for entry in entries},
                )
                claimed = (
                    parsed.entry_count,
                    parsed.first_entry_digest,
                    parsed.head_digest,
                    parsed.source_roots,
                    True,
                )
                if not chain_report.ok:
                    errors.append("evidence chain failed verification")
                    integrity = "failed"
                elif actual != claimed:
                    errors.append("receipt ledger summary does not match evidence store snapshot")
                    integrity = "failed"
                elif expected_identity_mismatch:
                    # Do not let successful store binding erase an explicit
                    # caller-supplied identity mismatch.
                    integrity = "failed"
                else:
                    integrity = "verified"
            except Exception:
                errors.append("could not verify evidence store snapshot")
                integrity = "failed"

    if (
        integrity == "failed"
        or authenticity == "bad-signature"
        or authenticity == "malformed"
        or completeness == "incomplete"
    ):
        run_verdict: Literal["verified", "failed", "unknown"] = "failed"
    elif integrity == "unknown" or authenticity == "unknown-key":
        run_verdict = "unknown"
    elif parsed.completion.status != "finished":
        run_verdict = "failed"
    elif parsed.completion.test_exit_code not in (None, 0):
        run_verdict = "failed"
    elif parsed.completion.verifier_verdict == "failed":
        run_verdict = "failed"
    elif parsed.completion.verifier_verdict != "passed":
        run_verdict = "unknown"
    else:
        run_verdict = "verified"

    return RunReceiptVerification(
        integrity,
        completeness,
        authenticity,
        run_verdict,
        parsed.run_id,
        parsed.signer_key_id,
        tuple(errors),
    )
