"""Strict, versioned data structures for Northstar run evidence.

Digests establish content identity only. A hash chain is not an authenticity
claim until a trusted signer seals its head in a separately verified manifest.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

EVIDENCE_ENTRY_SCHEMA_VERSION = "northstar.evidence-entry.v1"
DIGEST_PREFIX = "sha256:"
MAX_IDENTIFIER_CHARS = 128
MAX_SOURCE_ID_CHARS = 256
MAX_ENTRY_REFS = 128
MAX_SUBJECT_BYTES = 1_048_576
MAX_SAFE_INTEGER = (1 << 53) - 1

_ID_RE = re.compile(r"^[^\s/\\\x00-\x1f\x7f]+$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUBJECT_DOMAIN = b"northstar-evidence-subject.v1\0"
_ENTRY_DOMAIN = b"northstar-evidence-entry.v1\0"


def _identifier(value: Any, field: str, *, max_chars: int = MAX_IDENTIFIER_CHARS) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if len(value) > max_chars:
        raise ValueError(f"{field} is too long")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} must not contain whitespace, '/', '\\', or control characters")
    return value


def _label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase identifier")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if value <= 0:
        raise ValueError(f"{field} must be positive")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _json_value(value: Any, *, path: str = "$") -> Any:
    """Copy the interoperable JSON subset used by the evidence digest format."""
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path} integer exceeds the interoperable safe range")
        return value
    if isinstance(value, float):
        raise ValueError(f"{path} must not contain floating-point values; use a decimal string")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            if not key.isascii():
                raise ValueError(f"{path} object keys must be ASCII for stable cross-language ordering")
            result[key] = _json_value(item, path=f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise ValueError(f"{path} contains a non-JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON over ASCII keys and safe integers only."""
    normalized = _json_value(value)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("value cannot be represented as canonical JSON") from error


def digest_subject(subject: Mapping[str, Any] | bytes) -> str:
    """Hash a JSON mapping or exact bytes using the evidence subject domain."""
    if isinstance(subject, bytes):
        payload = subject
    elif isinstance(subject, Mapping):
        payload = canonical_json(subject)
    else:
        raise ValueError("subject must be a mapping or bytes")
    if len(payload) > MAX_SUBJECT_BYTES:
        raise ValueError(f"subject exceeds the {MAX_SUBJECT_BYTES}-byte limit")
    return DIGEST_PREFIX + hashlib.sha256(_SUBJECT_DOMAIN + payload).hexdigest()


def _entry_digest(body: Mapping[str, Any]) -> str:
    return DIGEST_PREFIX + hashlib.sha256(_ENTRY_DOMAIN + canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class EvidenceRef:
    """Typed reference to another piece of evidence, never an arbitrary path."""

    kind: str
    ref_id: str
    digest: str

    def __post_init__(self) -> None:
        _label(self.kind, "ref.kind")
        _identifier(self.ref_id, "ref.ref_id")
        _digest(self.digest, "ref.digest")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "ref_id": self.ref_id, "digest": self.digest}

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceRef":
        if not isinstance(value, dict):
            raise ValueError("evidence ref must be an object")
        expected = {"kind", "ref_id", "digest"}
        if set(value) != expected:
            missing = sorted(expected - set(value))
            unknown = sorted(set(value) - expected)
            details = []
            if missing:
                details.append(f"missing fields: {', '.join(missing)}")
            if unknown:
                details.append(f"unknown fields: {', '.join(unknown)}")
            raise ValueError("evidence ref " + "; ".join(details))
        return cls(kind=value["kind"], ref_id=value["ref_id"], digest=value["digest"])


@dataclass(frozen=True)
class EvidenceEntry:
    """One immutable, identity-bound claim in a run's evidence hash chain."""

    schema_version: str
    run_id: str
    sequence: int
    source: str
    kind: str
    occurred_at: int
    subject_digest: str
    refs: tuple[EvidenceRef, ...]
    previous_entry_digest: str | None
    source_id: str | None
    entry_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != EVIDENCE_ENTRY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {EVIDENCE_ENTRY_SCHEMA_VERSION}")
        _identifier(self.run_id, "run_id")
        _positive_integer(self.sequence, "sequence")
        _label(self.source, "source")
        _label(self.kind, "kind")
        _positive_integer(self.occurred_at, "occurred_at")
        _digest(self.subject_digest, "subject_digest")
        if not isinstance(self.refs, tuple) or len(self.refs) > MAX_ENTRY_REFS:
            raise ValueError(f"refs must be a tuple of at most {MAX_ENTRY_REFS} entries")
        if not all(isinstance(ref, EvidenceRef) for ref in self.refs):
            raise ValueError("refs must contain only EvidenceRef objects")
        for ref in self.refs:
            EvidenceRef.from_dict(ref.to_dict())
        ref_keys = [(ref.kind, ref.ref_id) for ref in self.refs]
        if len(ref_keys) != len(set(ref_keys)):
            raise ValueError("refs contain duplicate kind/ref_id pairs")
        if ref_keys != sorted(ref_keys):
            raise ValueError("refs must be sorted by kind and ref_id")
        if self.sequence == 1:
            if self.previous_entry_digest is not None:
                raise ValueError("the first entry must not have a previous_entry_digest")
        else:
            _digest(self.previous_entry_digest, "previous_entry_digest")
        if self.source_id is not None:
            _identifier(self.source_id, "source_id", max_chars=MAX_SOURCE_ID_CHARS)
        _digest(self.entry_digest, "entry_digest")
        expected = _entry_digest(self.body_dict())
        if self.entry_digest != expected:
            raise ValueError("entry_digest does not match canonical entry content")

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        sequence: int,
        source: str,
        kind: str,
        occurred_at: int,
        subject_digest: str,
        refs: tuple[EvidenceRef, ...] = (),
        previous_entry_digest: str | None = None,
        source_id: str | None = None,
    ) -> "EvidenceEntry":
        if not isinstance(refs, tuple) or len(refs) > MAX_ENTRY_REFS:
            raise ValueError(f"refs must be a tuple of at most {MAX_ENTRY_REFS} entries")
        if not all(isinstance(ref, EvidenceRef) for ref in refs):
            raise ValueError("refs must contain only EvidenceRef objects")
        refs = tuple(EvidenceRef.from_dict(ref.to_dict()) for ref in refs)
        refs = tuple(sorted(refs, key=lambda ref: (ref.kind, ref.ref_id)))
        body = {
            "schema_version": EVIDENCE_ENTRY_SCHEMA_VERSION,
            "run_id": run_id,
            "sequence": sequence,
            "source": source,
            "kind": kind,
            "occurred_at": occurred_at,
            "subject_digest": subject_digest,
            "refs": [ref.to_dict() for ref in refs],
            "previous_entry_digest": previous_entry_digest,
            "source_id": source_id,
        }
        return cls(
            schema_version=EVIDENCE_ENTRY_SCHEMA_VERSION,
            run_id=run_id,
            sequence=sequence,
            source=source,
            kind=kind,
            occurred_at=occurred_at,
            subject_digest=subject_digest,
            refs=refs,
            previous_entry_digest=previous_entry_digest,
            source_id=source_id,
            entry_digest=_entry_digest(body),
        )

    def body_dict(self) -> dict[str, Any]:
        """Canonical entry fields covered by ``entry_digest``."""
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "source": self.source,
            "kind": self.kind,
            "occurred_at": self.occurred_at,
            "subject_digest": self.subject_digest,
            "refs": [ref.to_dict() for ref in self.refs],
            "previous_entry_digest": self.previous_entry_digest,
            "source_id": self.source_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body_dict(), "entry_digest": self.entry_digest}

    def canonical_json(self) -> bytes:
        """Serialize this entry as canonical UTF-8 JSON (including its digest)."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceEntry":
        if not isinstance(value, dict):
            raise ValueError("evidence entry must be an object")
        expected = {
            "schema_version", "run_id", "sequence", "source", "kind", "occurred_at",
            "subject_digest", "refs", "previous_entry_digest", "source_id", "entry_digest",
        }
        if set(value) != expected:
            missing = sorted(expected - set(value))
            unknown = sorted(set(value) - expected)
            details = []
            if missing:
                details.append(f"missing fields: {', '.join(missing)}")
            if unknown:
                details.append(f"unknown fields: {', '.join(unknown)}")
            raise ValueError("evidence entry " + "; ".join(details))
        refs_value = value["refs"]
        if not isinstance(refs_value, list):
            raise ValueError("refs must be a list")
        refs = tuple(EvidenceRef.from_dict(ref) for ref in refs_value)
        return cls(
            schema_version=value["schema_version"],
            run_id=value["run_id"],
            sequence=value["sequence"],
            source=value["source"],
            kind=value["kind"],
            occurred_at=value["occurred_at"],
            subject_digest=value["subject_digest"],
            refs=refs,
            previous_entry_digest=value["previous_entry_digest"],
            source_id=value["source_id"],
            entry_digest=value["entry_digest"],
        )
