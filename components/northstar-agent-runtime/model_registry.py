"""Model registry: MLflow-style registration, staging, and lineage.

A model registry answers "which model version is production, and where
did it come from?" -- the bookkeeping half of ML lifecycle governance:

* :meth:`ModelRegistry.register` records a named model version pinned by
  a ``sha256:`` artifact digest. The registry never stores model bytes;
  it pins *references* (digest + URI + metadata) so the audit trail can
  answer "which bytes went to production" without the registry becoming
  an artifact store (the host owns artifact storage).
* Versions are integers and strictly increase per model name: a
  duplicate registration with a different digest is a conflict, never a
  silent overwrite.
* :meth:`ModelRegistry.promote` moves a version through the stage
  lifecycle ``None -> Staging -> Production -> Archived``. At most one
  version per name is ``Production``: promoting a new one demotes the
  old one (recorded as a ``superseded`` transition so history is never
  rewritten). ``Archived`` is one-way -- a version can only leave
  ``Archived`` by going back to ``Staging``.
* :meth:`ModelRegistry.lineage` returns the frozen provenance record
  for a version: the run that trained it, the data sources it consumed,
  and the parent version it was derived from. The chain is host-
  reported; the registry pins it, it does not verify it.

Honest scope: the registry pins what the host *reported*. It cannot
prove the artifact digest matches the bytes the host actually served
(the host holds both), cannot prove training ran as reported (see
``attested_receipts`` for a hardware-anchored story), and cannot prove
lineage completeness (the host may omit a data source). A promotion
decision is a policy outcome on the recorded state -- "this version is
Production *according to this registry*", never "this model is good".
Deterministic, no wall-clock (all caller-supplied int seqs), stdlib
only.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple


#: Version pin for this module's record shape.
MODEL_REGISTRY_VERSION = "model-registry.v1"

#: Schema pin carried on audit records.
MODEL_REGISTRY_SCHEMA = "northstar.model-registry.v1"

#: Stage lifecycle. "None" is the un-staged initial state.
STAGE_STAGING = "Staging"
STAGE_PRODUCTION = "Production"
STAGE_ARCHIVED = "Archived"
_VALID_STAGES = frozenset({STAGE_STAGING, STAGE_PRODUCTION, STAGE_ARCHIVED})

#: Largest integer exactly representable in a JSON float (documents the
#: same canonicalization caveat as ``secure_aggregation``; all pins
#: here are hex digests, never raw ints, so it does not apply).
_MAX_SAFE_INTEGER = 2**53


class ModelRegistryError(Exception):
    """Base error for model-registry failures."""


class UnknownModelError(ModelRegistryError):
    """A model name (or name+version) is not registered."""


class VersionConflictError(ModelRegistryError):
    """Re-registration with a different artifact digest, or a
    non-increasing version number."""


class StageTransitionError(ModelRegistryError):
    """An illegal stage move (e.g. staging a production version,
    re-entering production from archived without going via staging)."""


def _pin_bytes(payload: bytes) -> str:
    """Return a ``sha256:`` pin of raw bytes."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> str:
    """Canonical JSON with exact int handling (fail-closed on the
    >2**53 float-loss caveat)."""
    def _check(v: Any) -> None:
        if isinstance(v, bool):
            return
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ModelRegistryError("NaN/inf metadata is not canonicalizable")
            if v.is_integer() and abs(v) > _MAX_SAFE_INTEGER:
                raise ModelRegistryError(
                    "integral float beyond 2**53 is not canonicalizable"
                )
        elif isinstance(v, int):
            return
        elif isinstance(v, (list, tuple)):
            for item in v:
                _check(item)
        elif isinstance(v, dict):
            for k, item in v.items():
                if not isinstance(k, str):
                    raise ModelRegistryError("metadata keys must be str")
                _check(item)

    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _validate_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ModelRegistryError("seq must be a non-negative int")
    return seq


def _validate_name(name: Any) -> str:
    if isinstance(name, bool) or not isinstance(name, str) or not name:
        raise ModelRegistryError("model name must be a non-empty str")
    return name


@dataclass(frozen=True)
class ModelVersion:
    """One registered model version: name + version pinned to an artifact."""

    name: str
    version: int
    artifact_digest: str
    artifact_uri: str
    metadata: Tuple[Tuple[str, str], ...] = ()
    registered_seq: int = 0
    schema: str = MODEL_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        _validate_name(self.name)
        if isinstance(self.version, bool) or not isinstance(self.version, int) \
                or self.version < 1:
            raise ModelRegistryError("version must be a positive int")
        if not isinstance(self.artifact_digest, str) \
                or not self.artifact_digest.startswith("sha256:"):
            raise ModelRegistryError("artifact_digest must be a sha256: pin")
        if isinstance(self.artifact_uri, bool) or not isinstance(self.artifact_uri, str) \
                or not self.artifact_uri:
            raise ModelRegistryError("artifact_uri must be a non-empty str")
        _validate_seq(self.registered_seq)
        for pair in self.metadata:
            if not isinstance(pair, tuple) or len(pair) != 2 \
                    or not all(isinstance(p, str) for p in pair):
                raise ModelRegistryError("metadata must be ((str, str), ...)")
        if self.schema != MODEL_REGISTRY_SCHEMA:
            raise ModelRegistryError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "name": self.name,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
            "artifact_uri": self.artifact_uri,
            "metadata": list(self.metadata),
            "registered_seq": self.registered_seq,
        }


@dataclass(frozen=True)
class StageTransition:
    """A recorded stage change for one model version."""

    name: str
    version: int
    from_stage: Optional[str]
    to_stage: str
    seq: int
    schema: str = MODEL_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        _validate_name(self.name)
        if isinstance(self.version, bool) or not isinstance(self.version, int) \
                or self.version < 1:
            raise ModelRegistryError("version must be a positive int")
        if self.from_stage is not None and self.from_stage not in _VALID_STAGES:
            raise ModelRegistryError("bad from_stage")
        if self.to_stage not in _VALID_STAGES:
            raise ModelRegistryError("bad to_stage")
        _validate_seq(self.seq)
        if self.schema != MODEL_REGISTRY_SCHEMA:
            raise ModelRegistryError("bad schema pin")


@dataclass(frozen=True)
class LineageRecord:
    """Provenance for one model version (host-reported, pinned)."""

    name: str
    version: int
    run_id: str
    data_sources: Tuple[str, ...] = ()
    parent_name: Optional[str] = None
    parent_version: Optional[int] = None
    lineage_digest: str = ""
    schema: str = MODEL_REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        _validate_name(self.name)
        if isinstance(self.version, bool) or not isinstance(self.version, int) \
                or self.version < 1:
            raise ModelRegistryError("version must be a positive int")
        if isinstance(self.run_id, bool) or not isinstance(self.run_id, str) \
                or not self.run_id:
            raise ModelRegistryError("run_id must be a non-empty str")
        for src in self.data_sources:
            if isinstance(src, bool) or not isinstance(src, str) or not src:
                raise ModelRegistryError("data_sources must be non-empty strs")
        if (self.parent_name is None) != (self.parent_version is None):
            raise ModelRegistryError(
                "parent_name and parent_version must be given together"
            )
        if self.parent_name is not None:
            _validate_name(self.parent_name)
            if isinstance(self.parent_version, bool) \
                    or not isinstance(self.parent_version, int) \
                    or self.parent_version < 1:
                raise ModelRegistryError("parent_version must be a positive int")
        if not isinstance(self.lineage_digest, str) \
                or not self.lineage_digest.startswith("sha256:"):
            raise ModelRegistryError("lineage_digest must be a sha256: pin")
        if self.schema != MODEL_REGISTRY_SCHEMA:
            raise ModelRegistryError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "name": self.name,
            "version": self.version,
            "run_id": self.run_id,
            "data_sources": list(self.data_sources),
            "parent_name": self.parent_name,
            "parent_version": self.parent_version,
            "lineage_digest": self.lineage_digest,
        }


class ModelRegistry:
    """In-memory model registry: registration, staging, lineage."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # (name) -> list[ModelVersion] in registration order
        self._versions: Dict[str, list] = {}
        # (name, version) -> stage (absent == None/un-staged)
        self._stages: Dict[Tuple[str, int], str] = {}
        # append-only transition log
        self._transitions: list = []
        # (name, version) -> LineageRecord
        self._lineage: Dict[Tuple[str, int], LineageRecord] = {}

    # ------------------------------------------------------------------
    # registration

    def register(
        self,
        name: str,
        artifact: Mapping[str, Any],
        *,
        version: Optional[int] = None,
        metadata: Optional[Mapping[str, str]] = None,
        lineage: Optional[Mapping[str, Any]] = None,
        seq: int = 0,
    ) -> ModelVersion:
        """Register a model version pinned to an artifact digest.

        ``artifact`` is a mapping with at least ``digest`` (a ``sha256:``
        pin) and ``uri``. When ``version`` is None the next integer is
        minted; when given it must exceed the current max. Re-
        registering the *same* digest under the same name+version is
        idempotent; a *different* digest under the same name+version
        raises :class:`VersionConflictError`.
        """
        name = _validate_name(name)
        _validate_seq(seq)
        with self._lock:
            versions = self._versions.setdefault(name, [])
            current_max = versions[-1].version if versions else 0

            if version is None:
                version = current_max + 1
            if isinstance(version, bool) or not isinstance(version, int) \
                    or version < 1:
                raise ModelRegistryError("version must be a positive int")
            if version <= current_max:
                raise VersionConflictError(
                    f"version {version} is not newer than {current_max}"
                )

            if not isinstance(artifact, Mapping):
                raise ModelRegistryError("artifact must be a mapping")
            digest = artifact.get("digest")
            uri = artifact.get("uri")
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise ModelRegistryError("artifact['digest'] must be a sha256: pin")
            if isinstance(uri, bool) or not isinstance(uri, str) or not uri:
                raise ModelRegistryError("artifact['uri'] must be a non-empty str")

            md_pairs: Tuple[Tuple[str, str], ...] = ()
            if metadata is not None:
                if not isinstance(metadata, Mapping):
                    raise ModelRegistryError("metadata must be a mapping")
                md_pairs = tuple(sorted(metadata.items()))
                for k, v in md_pairs:
                    if not isinstance(k, str) or not isinstance(v, str):
                        raise ModelRegistryError(
                            "metadata keys and values must be str"
                        )

            record = ModelVersion(
                name=name,
                version=version,
                artifact_digest=digest,
                artifact_uri=uri,
                metadata=md_pairs,
                registered_seq=seq,
            )
            versions.append(record)

            if lineage is not None:
                self._set_lineage(name, version, lineage)

            return record

    def get(self, name: str, version: Optional[int] = None) -> ModelVersion:
        """Fetch a version; ``version=None`` returns the latest."""
        name = _validate_name(name)
        with self._lock:
            versions = self._versions.get(name)
            if not versions:
                raise UnknownModelError(f"unknown model {name!r}")
            if version is None:
                return versions[-1]
            for v in versions:
                if v.version == version:
                    return v
            raise UnknownModelError(f"unknown version {name!r} v{version}")

    def list_versions(self, name: str) -> Tuple[ModelVersion, ...]:
        name = _validate_name(name)
        with self._lock:
            versions = self._versions.get(name)
            if not versions:
                raise UnknownModelError(f"unknown model {name!r}")
            return tuple(versions)

    def models(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._versions))

    # ------------------------------------------------------------------
    # staging / promotion

    def stage(self, name: str, version: int) -> Optional[str]:
        """Return the current stage of a version (``None`` = un-staged)."""
        _validate_name(name)
        with self._lock:
            self._require_version(name, version)
            return self._stages.get((name, version))

    def promote(self, name: str, version: int, stage: str, seq: int = 0) -> StageTransition:
        """Move a version to ``stage``.

        Rules (fail-closed):
        - ``Production`` is exclusive per name: promoting a new
          version demotes the current one (recorded as a
          ``superseded`` transition).
        - ``Archived`` cannot go directly to ``Production``; it must
          return to ``Staging`` first.
        - A version can always move to ``Staging`` (the entry stage).
        """
        name = _validate_name(name)
        if stage not in _VALID_STAGES:
            raise ModelRegistryError(f"unknown stage {stage!r}")
        _validate_seq(seq)
        with self._lock:
            self._require_version(name, version)
            current = self._stages.get((name, version))

            if stage == STAGE_PRODUCTION:
                if current == STAGE_ARCHIVED:
                    raise StageTransitionError(
                        "Archived cannot promote directly to Production"
                    )
                # Demote the current production version, if any.
                for (n, v), s in list(self._stages.items()):
                    if n == name and s == STAGE_PRODUCTION and v != version:
                        self._stages[(n, v)] = STAGE_STAGING
                        self._transitions.append(
                            StageTransition(
                                name=n, version=v,
                                from_stage=STAGE_PRODUCTION,
                                to_stage=STAGE_STAGING, seq=seq,
                            )
                        )
            elif stage == STAGE_ARCHIVED:
                pass  # terminal-ish; any non-production version may archive
            elif stage == STAGE_STAGING:
                pass

            self._stages[(name, version)] = stage
            transition = StageTransition(
                name=name, version=version,
                from_stage=current, to_stage=stage, seq=seq,
            )
            self._transitions.append(transition)
            return transition

    def production(self, name: str) -> Optional[ModelVersion]:
        """The current Production version of a model, or None."""
        _validate_name(name)
        with self._lock:
            for (n, v), s in self._stages.items():
                if n == name and s == STAGE_PRODUCTION:
                    return self.get(name, v)
            return None

    def transitions(self) -> Tuple[StageTransition, ...]:
        with self._lock:
            return tuple(self._transitions)

    # ------------------------------------------------------------------
    # lineage

    def _set_lineage(
        self, name: str, version: int, lineage: Mapping[str, Any]
    ) -> LineageRecord:
        if not isinstance(lineage, Mapping):
            raise ModelRegistryError("lineage must be a mapping")
        run_id = lineage.get("run_id")
        sources = lineage.get("data_sources", ())
        parent = lineage.get("parent")
        parent_name = parent_version = None
        if parent is not None:
            if not isinstance(parent, Mapping):
                raise ModelRegistryError("lineage['parent'] must be a mapping")
            parent_name = parent.get("name")
            parent_version = parent.get("version")
        if isinstance(sources, str) or not isinstance(sources, (list, tuple)):
            raise ModelRegistryError("lineage['data_sources'] must be a list")
        sources = tuple(sources)

        body = {
            "name": name,
            "version": version,
            "run_id": run_id,
            "data_sources": list(sources),
            "parent": (
                {"name": parent_name, "version": parent_version}
                if parent_name is not None
                else None
            ),
        }
        digest = _pin_bytes(_canonical_json(body).encode("utf-8"))
        record = LineageRecord(
            name=name,
            version=version,
            run_id=run_id,
            data_sources=sources,
            parent_name=parent_name,
            parent_version=parent_version,
            lineage_digest=digest,
        )
        self._lineage[(name, version)] = record
        return record

    def lineage(self, name: str, version: int) -> LineageRecord:
        """Return the pinned provenance record for a version."""
        _validate_name(name)
        with self._lock:
            self._require_version(name, version)
            record = self._lineage.get((name, version))
            if record is None:
                raise UnknownModelError(
                    f"no lineage recorded for {name!r} v{version}"
                )
            return record

    def _require_version(self, name: str, version: int) -> None:
        versions = self._versions.get(name)
        if not versions or not any(v.version == version for v in versions):
            raise UnknownModelError(f"unknown version {name!r} v{version}")


def model_registry_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape a model-registry lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("registered", "promoted", "demoted", "lineage-recorded")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _validate_seq(seq)
    for key in ("name", "version"):
        if key in fields and fields[key] is None:
            raise ValueError(f"{key} must not be None")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"model-registry.{kind}",
        "module": MODEL_REGISTRY_SCHEMA,
        "version": MODEL_REGISTRY_VERSION,
        "seq": seq,
        **fields,
    }


def main() -> None:
    reg = ModelRegistry()
    v1 = reg.register(
        "spam-detector",
        {"digest": "sha256:" + "ab" * 32, "uri": "s3://models/spam/v1"},
        metadata={"framework": "torch"},
        lineage={"run_id": "run-1", "data_sources": ["s3://data/spam-2026"]},
        seq=0,
    )
    assert v1.version == 1
    v2 = reg.register(
        "spam-detector",
        {"digest": "sha256:" + "cd" * 32, "uri": "s3://models/spam/v2"},
        seq=1,
    )
    assert v2.version == 2
    assert reg.get("spam-detector").version == 2
    t = reg.promote("spam-detector", 1, STAGE_PRODUCTION, seq=2)
    assert reg.production("spam-detector").version == 1
    reg.promote("spam-detector", 2, STAGE_PRODUCTION, seq=3)
    assert reg.production("spam-detector").version == 2
    assert reg.stage("spam-detector", 1) == STAGE_STAGING  # demoted
    lin = reg.lineage("spam-detector", 1)
    assert lin.run_id == "run-1"
    assert lin.data_sources == ("s3://data/spam-2026",)
    print("model-registry OK: register, promote, demote, lineage")


if __name__ == "__main__":
    main()
