"""Bounded, versioned artifact manifests for governed tool receipts.

An artifact manifest is an observation returned by a tool, not an authorization
or a claim of host attestation. It gives custom tools a structured way to report
outputs that are not captured by the workspace ``path``/``paths`` impact set.
The runtime validates the shape and carries the canonical manifest into the
signed action receipt; it never treats a manifest as permission to write.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping

ARTIFACT_MANIFEST_SCHEMA_VERSION = "northstar.artifact-manifest.v1"
MAX_ARTIFACTS = 64
MAX_ARTIFACT_ID_CHARS = 128
MAX_LOCATOR_CHARS = 2048
MAX_MEDIA_TYPE_CHARS = 128
_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_KINDS = frozenset({"file", "directory", "uri", "opaque"})


class ArtifactError(ValueError):
    """An artifact manifest is malformed or exceeds its bounded contract."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ArtifactError(f"cannot canonicalize artifact manifest: {error}") from error


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ARTIFACT_ID_RE.fullmatch(value):
        raise ArtifactError(f"{field} is invalid")
    return value


def _require_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ArtifactError(f"{field} is invalid")
    if any(ord(char) < 0x20 for char in value):
        raise ArtifactError(f"{field} contains control characters")
    return value


def _require_locator(value: Any, kind: str) -> str:
    locator = _require_text(value, "locator", MAX_LOCATOR_CHARS)
    if kind in {"file", "directory"}:
        if locator.startswith(("/", "\\")) or "\\" in locator:
            raise ArtifactError("workspace artifact locator must be relative")
        if any(part in {"", ".", ".."} for part in locator.split("/")):
            raise ArtifactError("workspace artifact locator is not normalized")
    return locator


def _require_digest(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ArtifactError("digest must be a lowercase sha256 digest")
    return value


def _require_bytes(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ArtifactError("bytes must be a non-negative integer")
    return value


@dataclass(frozen=True)
class Artifact:
    """One bounded output reference reported by a tool."""

    artifact_id: str
    kind: str
    locator: str
    digest: str | None = None
    bytes: int | None = None
    media_type: str | None = None

    _fields: ClassVar[tuple[str, ...]] = (
        "artifact_id",
        "kind",
        "locator",
        "digest",
        "bytes",
        "media_type",
    )

    def __post_init__(self) -> None:
        _require_id(self.artifact_id, "artifact_id")
        if self.kind not in _KINDS:
            raise ArtifactError("kind is invalid")
        _require_locator(self.locator, self.kind)
        _require_digest(self.digest)
        _require_bytes(self.bytes)
        if self.media_type is not None:
            _require_text(self.media_type, "media_type", MAX_MEDIA_TYPE_CHARS)

    @classmethod
    def from_mapping(cls, value: Any) -> "Artifact":
        if not isinstance(value, Mapping):
            raise ArtifactError("artifact must be an object")
        expected = set(cls._fields)
        actual = set(value)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            raise ArtifactError(f"artifact missing fields: {', '.join(missing)}")
        if unknown:
            raise ArtifactError(f"artifact has unknown fields: {', '.join(unknown)}")
        return cls(
            artifact_id=value["artifact_id"],
            kind=value["kind"],
            locator=value["locator"],
            digest=value["digest"],
            bytes=value["bytes"],
            media_type=value["media_type"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "locator": self.locator,
            "digest": self.digest,
            "bytes": self.bytes,
            "media_type": self.media_type,
        }


@dataclass(frozen=True)
class ArtifactManifest:
    """Validated bounded collection of tool-reported artifact references."""

    artifacts: tuple[Artifact, ...]
    schema_version: str = ARTIFACT_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION:
            raise ArtifactError(f"schema_version must be {ARTIFACT_MANIFEST_SCHEMA_VERSION}")
        if not isinstance(self.artifacts, (tuple, list)) or len(self.artifacts) > MAX_ARTIFACTS:
            raise ArtifactError("artifacts must be a bounded list")
        normalized = tuple(
            item if isinstance(item, Artifact) else Artifact.from_mapping(item)
            for item in self.artifacts
        )
        if len({item.artifact_id for item in normalized}) != len(normalized):
            raise ArtifactError("artifact_id values must be unique")
        if len({(item.kind, item.locator) for item in normalized}) != len(normalized):
            raise ArtifactError("artifact kind and locator pairs must be unique")
        object.__setattr__(self, "artifacts", normalized)

    @classmethod
    def from_mapping(cls, value: Any) -> "ArtifactManifest":
        if not isinstance(value, Mapping):
            raise ArtifactError("artifact_manifest must be an object")
        expected = {"schema_version", "artifacts"}
        actual = set(value)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            raise ArtifactError(f"artifact_manifest missing fields: {', '.join(missing)}")
        if unknown:
            raise ArtifactError(f"artifact_manifest has unknown fields: {', '.join(unknown)}")
        artifacts = value["artifacts"]
        if not isinstance(artifacts, list):
            raise ArtifactError("artifact_manifest artifacts must be a list")
        return cls(
            schema_version=value["schema_version"],
            artifacts=tuple(Artifact.from_mapping(item) for item in artifacts),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    def canonical_json(self) -> bytes:
        """Return deterministic bytes suitable for an outer receipt signature."""
        return _canonical_json(self.to_dict())

    def digest(self) -> str:
        """Return the canonical digest of the manifest itself."""
        return "sha256:" + hashlib.sha256(self.canonical_json()).hexdigest()


__all__ = [
    "ARTIFACT_MANIFEST_SCHEMA_VERSION",
    "MAX_ARTIFACTS",
    "Artifact",
    "ArtifactError",
    "ArtifactManifest",
]
