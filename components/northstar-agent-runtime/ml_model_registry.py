"""ML model registry: MLflow-shaped run-to-registry lifecycle.

This module is the *tracking bridge* layer of the ML lifecycle ledger,
deliberately distinct from ``model_registry`` (which owns named-model
registration, ``promote`` staging, and training lineage): here the focus
is the **experiment-to-registry handoff** that MLflow's
``mlflow.register_model(model_uri, name)`` performs.

* :meth:`MLModelRegistry.register` creates a *registered model name* --
  the container a model lives under. Optionally pins the creating run
  (``run_id``) and artifact source (``source`` URI); bytes never enter a
  record, only ``sha256:`` digests and string references.
* :meth:`MLModelRegistry.version` mints version ``N+1`` under a
  registered name (auto-incrementing, caller never picks the number),
  pinning the artifact digest and the source run that produced it.
  Every version is immutable once booked.
* :meth:`MLModelRegistry.stage` transitions a version through
  ``None -> Staging -> Production -> Archived``. At most one version per
  name may hold ``Production``: passing ``archive_existing=True`` moves
  the current production version to ``Archived`` in the same transition
  (MLflow transition semantics); without it, a competing production
  version fails closed. ``Archived`` is one-way -- a version leaves
  ``Archived`` only by returning to ``Staging``.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
(``hashlib``/``json``/``threading``/``dataclasses``/``typing``),
``sha256:`` digest pins, ``audit.ndjson/1`` events.

Honest scope: the registry pins what the host *reported* -- run ids,
artifact digests, source URIs. It cannot prove the artifact bytes behind
a digest are what the host served, cannot prove the reported run trained
the model, and cannot prove a stage label means the model is good. A
staged version is ledger truth: "this version is Production *according
to this registry*", never "this model is fit for production".

Version pin: ml-model-registry.v1
Schema pin: northstar.ml-model-registry.v1
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


#: Module version pin for records produced here.
ML_MODEL_REGISTRY_VERSION = "ml-model-registry.v1"

#: Schema pin carried on records.
ML_MODEL_REGISTRY_SCHEMA = "northstar.ml-model-registry.v1"

#: Audit-event schema pin.
_AUDIT_SCHEMA = "audit.ndjson/1"

#: Stage vocabulary. UNSTAGED is the initial state of a fresh version.
STAGE_UNSTAGED = "None"
STAGE_STAGING = "Staging"
STAGE_PRODUCTION = "Production"
STAGE_ARCHIVED = "Archived"
_VALID_STAGES = frozenset({STAGE_STAGING, STAGE_PRODUCTION, STAGE_ARCHIVED})

#: Largest integer exactly representable in a JSON float.
_MAX_SAFE_INTEGER = 2**53

#: Maximum string length for ids / URIs.
_MAX_STR_LEN = 4096


class MLModelRegistryError(Exception):
    """Base error for ml-model-registry failures."""


class BadNameError(MLModelRegistryError):
    """A model name failed validation."""


class DuplicateModelError(MLModelRegistryError):
    """A model name is already registered."""


class UnknownModelError(MLModelRegistryError):
    """A model name is not registered."""


class BadRunError(MLModelRegistryError):
    """A run id failed validation."""


class BadSourceError(MLModelRegistryError):
    """A source URI failed validation."""


class BadDigestError(MLModelRegistryError):
    """An artifact digest failed validation."""


class BadVersionError(MLModelRegistryError):
    """A version number failed validation."""


class UnknownVersionError(MLModelRegistryError):
    """A (name, version) pair is not booked."""


class BadStageError(MLModelRegistryError):
    """A stage name failed validation."""


class StageConflictError(MLModelRegistryError):
    """A stage transition is not allowed: illegal move, or another
    version already holds the target stage."""


class SeqOrderError(MLModelRegistryError):
    """The caller seq is not a strictly increasing non-negative int."""


class AuditKindError(MLModelRegistryError):
    """An unknown audit kind was requested."""


def _pin_bytes(payload: bytes) -> str:
    """Return a ``sha256:`` pin of raw bytes."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> str:
    """Canonical JSON; fail-closed on non-encodable / unsafe values."""

    def _check(v: Any) -> None:
        if isinstance(v, bool) or v is None:
            return
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise MLModelRegistryError("NaN/inf values are not canonicalizable")
            if v.is_integer() and abs(v) > _MAX_SAFE_INTEGER:
                raise MLModelRegistryError(
                    "integral float beyond 2**53 is not canonicalizable"
                )
            return
        if isinstance(v, int):
            if abs(v) >= _MAX_SAFE_INTEGER:
                raise MLModelRegistryError("|int| >= 2**53 is not canonicalizable")
            return
        if isinstance(v, str):
            if len(v) > _MAX_STR_LEN:
                raise MLModelRegistryError("string exceeds length guardrail")
            return
        if isinstance(v, (list, tuple)):
            for item in v:
                _check(item)
            return
        if isinstance(v, dict):
            for k, item in v.items():
                if not isinstance(k, str):
                    raise MLModelRegistryError("mapping keys must be str")
                _check(item)
            return
        raise MLModelRegistryError(
            "value type %s is not canonicalizable" % type(v).__name__
        )

    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _pin_value(value: Any) -> str:
    """Type-tagged ``sha256:`` pin of a canonicalizable value."""
    if isinstance(value, bool):
        tag = b"b"
    elif isinstance(value, int):
        tag = b"i"
    elif isinstance(value, float):
        tag = b"f"
    elif value is None:
        tag = b"n"
    elif isinstance(value, str):
        tag = b"s"
    else:
        tag = b"j"
    return _pin_bytes(tag + _canonical_json(value).encode("utf-8"))


def _validate_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


def _validate_name(name: Any) -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise BadNameError("model name must be a str")
    if not name.strip() or len(name) > 256:
        raise BadNameError("model name must be non-empty and <= 256 chars")
    return name


def _validate_opt_str(value: Any, exc: type, label: str, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise exc("%s must be a str" % label)
    if len(value) > max_len:
        raise exc("%s exceeds %d chars" % (label, max_len))
    return value


def _validate_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadDigestError("artifact digest must be a str")
    if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
        raise BadDigestError("artifact digest must be 'sha256:' + 64 hex chars")
    body = digest[len("sha256:"):]
    if any(c not in "0123456789abcdef" for c in body):
        raise BadDigestError("artifact digest hex body is malformed")
    return digest


def _validate_version(version: Any) -> int:
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise BadVersionError("version must be a positive int")
    return version


def _validate_stage(stage: Any) -> str:
    if stage not in _VALID_STAGES:
        raise BadStageError(
            "stage must be one of %s" % sorted(_VALID_STAGES)
        )
    return stage


# Audit event kinds.
_AUDIT_KINDS = (
    "ml-model.registered",
    "ml-model.versioned",
    "ml-model.staged",
    "ml-model.archived-existing",
    "ml-model.rejected",
)


def ml_model_registry_audit_event(
    kind: str, name: str, seq: int, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` audit record for this module.

    Raw artifact digests, run ids, and source URIs are pinned ids, never
    byte payloads; no raw model metadata crosses the audit boundary.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError("unknown audit kind: %r" % (kind,))
    _validate_seq(seq)
    body: Dict[str, Any] = {
        "schema": _AUDIT_SCHEMA,
        "kind": kind,
        "module": ML_MODEL_REGISTRY_VERSION,
        "name": name,
        "seq": seq,
    }
    if detail:
        for key, value in detail.items():
            if key in ("payload", "value", "raw", "metadata", "bytes"):
                raise AuditKindError("banned audit detail key: %r" % (key,))
            _pin_value(value)
            body[key] = value
    return body


@dataclass(frozen=True)
class RegisteredModel:
    """A registered model name (the container versions live under)."""

    name: str
    registered_seq: int
    run_id: str = ""
    source: str = ""
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin_bytes(
            ("ml-model|" + self.name + "|" + self.run_id + "|" + self.source).encode(
                "utf-8"
            )
        )


@dataclass(frozen=True)
class ModelVersionRecord:
    """One immutable version booked under a registered model name."""

    name: str
    version: int
    booked_seq: int
    artifact_digest: str
    source_run_id: str = ""
    stage: str = STAGE_UNSTAGED
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin_bytes(
            (
                "ml-version|"
                + self.name
                + "|"
                + str(self.version)
                + "|"
                + self.artifact_digest
                + "|"
                + self.source_run_id
                + "|"
                + self.stage
            ).encode("utf-8")
        )


@dataclass(frozen=True)
class StageRecord:
    """A recorded stage transition for one version."""

    name: str
    version: int
    from_stage: str
    to_stage: str
    seq: int
    archive_existing: bool
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin_bytes(
            (
                "ml-stage|"
                + self.name
                + "|"
                + str(self.version)
                + "|"
                + self.from_stage
                + "|"
                + self.to_stage
                + "|"
                + str(self.seq)
            ).encode("utf-8")
        )


class MLModelRegistry:
    """MLflow-shaped registered-model lifecycle ledger.

    * :meth:`register` -- create the model name container.
    * :meth:`version` -- mint the next version (auto-incremented).
    * :meth:`stage` -- move a version through the stage lifecycle.

    All mutations take a caller-supplied strictly increasing int ``seq``;
    failed mutations consume their seq and book a
    ``ml-model.rejected`` audit row (the batch-21 claim-then-burn
    discipline). Pure read views validate the seq shape, consume nothing,
    and write no audit row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._models: Dict[str, RegisteredModel] = {}
        self._versions: Dict[Tuple[str, int], ModelVersionRecord] = {}
        self._next_version: Dict[str, int] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers ------------------------------------------------

    def _claim(self, seq: Any) -> int:
        """Claim a strictly increasing seq; rewinds raise bare."""
        seq = _validate_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    "seq must be strictly increasing (last=%d, got=%d)"
                    % (self._last_seq, seq)
                )
            self._last_seq = seq
        return seq

    def _reject(self, name: str, seq: int, reason: str, error: Exception) -> Exception:
        with self._lock:
            self._audit.append(
                ml_model_registry_audit_event(
                    "ml-model.rejected",
                    name,
                    seq,
                    {"reason": reason, "error": type(error).__name__},
                )
            )
        return error

    def _guarded(self, name: str, seq: int, reason: str, func):  # type: ignore[no-untyped-def]
        """Run func; on failure consume the seq, book rejection, re-raise."""
        try:
            return func()
        except SeqOrderError:
            raise
        except Exception as exc:  # noqa: BLE001 -- fail-closed wrapping
            raise self._reject(name, seq, reason, exc) from exc

    # -- mutations -------------------------------------------------------

    def register(self, name: str, seq: int, run_id: str = "", source: str = "") -> RegisteredModel:
        """Register a model name.

        ``run_id`` pins the creating experiment run; ``source`` pins the
        artifact source URI. Duplicate names are refused fail-closed.
        """
        seq = self._claim(seq)

        def _do() -> RegisteredModel:
            _validate_name(name)
            _validate_opt_str(run_id, BadRunError, "run_id")
            _validate_opt_str(source, BadSourceError, "source", _MAX_STR_LEN)
            with self._lock:
                if name in self._models:
                    raise DuplicateModelError("model %r already registered" % name)
                record = RegisteredModel(
                    name=name,
                    registered_seq=seq,
                    run_id=run_id,
                    source=source,
                    digest=_pin_bytes(
                        ("ml-model|" + name + "|" + run_id + "|" + source).encode(
                            "utf-8"
                        )
                    ),
                )
                self._models[name] = record
                self._next_version[name] = 1
                self._audit.append(
                    ml_model_registry_audit_event(
                        "ml-model.registered",
                        name,
                        seq,
                        {"run_id": run_id, "source": source},
                    )
                )
                return record

        return self._guarded(name, seq, "register", _do)

    def version(
        self,
        name: str,
        seq: int,
        artifact_digest: str = "",
        source_run_id: str = "",
    ) -> ModelVersionRecord:
        """Mint the next auto-incremented version under ``name``.

        The artifact is pinned by digest only -- bytes never enter a
        record. ``source_run_id`` pins the experiment run that produced
        the artifact. Unknown names are refused fail-closed.
        """
        seq = self._claim(seq)

        def _do() -> ModelVersionRecord:
            _validate_name(name)
            if artifact_digest:
                _validate_digest(artifact_digest)
            _validate_opt_str(source_run_id, BadRunError, "source_run_id")
            with self._lock:
                if name not in self._models:
                    raise UnknownModelError("model %r not registered" % name)
                number = self._next_version[name]
                digest = _pin_bytes(
                    (
                        "ml-version|"
                        + name
                        + "|"
                        + str(number)
                        + "|"
                        + artifact_digest
                        + "|"
                        + source_run_id
                        + "|"
                        + STAGE_UNSTAGED
                    ).encode("utf-8")
                )
                record = ModelVersionRecord(
                    name=name,
                    version=number,
                    booked_seq=seq,
                    artifact_digest=artifact_digest,
                    source_run_id=source_run_id,
                    stage=STAGE_UNSTAGED,
                    digest=digest,
                )
                self._versions[(name, number)] = record
                self._next_version[name] = number + 1
                self._audit.append(
                    ml_model_registry_audit_event(
                        "ml-model.versioned",
                        name,
                        seq,
                        {
                            "version": number,
                            "artifact_digest": artifact_digest,
                            "source_run_id": source_run_id,
                        },
                    )
                )
                return record

        return self._guarded(name, seq, "version", _do)

    def stage(
        self,
        name: str,
        version: int,
        new_stage: str,
        seq: int,
        archive_existing: bool = False,
    ) -> StageRecord:
        """Move version ``(name, version)`` to ``new_stage``.

        Allowed moves: ``None -> Staging``, ``Staging -> Production``,
        ``Production -> Archived``, ``Staging -> Archived``,
        ``Archived -> Staging``. At most one version per name holds
        ``Production``: if another version already holds it and
        ``archive_existing`` is False the move fails closed; with True the
        existing production version is moved to ``Archived`` in the same
        transition (booked as a separate ``ml-model.archived-existing``
        audit row).
        """
        seq = self._claim(seq)

        def _do() -> StageRecord:
            _validate_name(name)
            _validate_version(version)
            _validate_stage(new_stage)
            with self._lock:
                key = (name, version)
                current = self._versions.get(key)
                if current is None:
                    raise UnknownVersionError(
                        "version %r of model %r not booked" % (version, name)
                    )
                from_stage = current.stage
                if not self._stage_move_allowed(from_stage, new_stage):
                    raise StageConflictError(
                        "illegal stage move %r -> %r" % (from_stage, new_stage)
                    )
                if new_stage == STAGE_PRODUCTION:
                    holder = self._production_holder(name)
                    if holder is not None and holder != version:
                        if not archive_existing:
                            raise StageConflictError(
                                "version %r already holds Production for %r"
                                % (holder, name)
                            )
                        self._apply_stage(name, holder, STAGE_PRODUCTION, STAGE_ARCHIVED, seq)
                        self._audit.append(
                            ml_model_registry_audit_event(
                                "ml-model.archived-existing",
                                name,
                                seq,
                                {"version": holder},
                            )
                        )
                self._apply_stage(name, version, from_stage, new_stage, seq)
                record = StageRecord(
                    name=name,
                    version=version,
                    from_stage=from_stage,
                    to_stage=new_stage,
                    seq=seq,
                    archive_existing=archive_existing,
                    digest=_pin_bytes(
                        (
                            "ml-stage|"
                            + name
                            + "|"
                            + str(version)
                            + "|"
                            + from_stage
                            + "|"
                            + new_stage
                            + "|"
                            + str(seq)
                        ).encode("utf-8")
                    ),
                )
                self._audit.append(
                    ml_model_registry_audit_event(
                        "ml-model.staged",
                        name,
                        seq,
                        {
                            "version": version,
                            "from_stage": from_stage,
                            "to_stage": new_stage,
                            "archive_existing": archive_existing,
                        },
                    )
                )
                return record

        return self._guarded(name, seq, "stage", _do)

    # -- views -----------------------------------------------------------

    def model(self, name: str) -> Optional[RegisteredModel]:
        """Return the registered model record, or None."""
        with self._lock:
            return self._models.get(name)

    def version_record(self, name: str, version: int) -> Optional[ModelVersionRecord]:
        """Return one version record, or None."""
        with self._lock:
            return self._versions.get((name, version))

    def versions(self, name: str) -> Tuple[ModelVersionRecord, ...]:
        """All versions under ``name`` in ascending order."""
        with self._lock:
            return tuple(
                sorted(
                    (r for (n, _), r in self._versions.items() if n == name),
                    key=lambda r: r.version,
                )
            )

    def model_names(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._models))

    def production_version(self, name: str) -> Optional[int]:
        """Version number currently holding Production, or None."""
        with self._lock:
            return self._production_holder(name)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _stage_move_allowed(from_stage: str, to_stage: str) -> bool:
        allowed = {
            STAGE_UNSTAGED: {STAGE_STAGING},
            STAGE_STAGING: {STAGE_PRODUCTION, STAGE_ARCHIVED},
            STAGE_PRODUCTION: {STAGE_ARCHIVED},
            STAGE_ARCHIVED: {STAGE_STAGING},
        }
        return to_stage in allowed.get(from_stage, set())

    def _production_holder(self, name: str) -> Optional[int]:
        for (n, v), record in self._versions.items():
            if n == name and record.stage == STAGE_PRODUCTION:
                return v
        return None

    def _apply_stage(
        self, name: str, version: int, from_stage: str, to_stage: str, seq: int
    ) -> None:
        key = (name, version)
        current = self._versions[key]
        new_digest = _pin_bytes(
            (
                "ml-version|"
                + name
                + "|"
                + str(version)
                + "|"
                + current.artifact_digest
                + "|"
                + current.source_run_id
                + "|"
                + to_stage
            ).encode("utf-8")
        )
        self._versions[key] = ModelVersionRecord(
            name=name,
            version=version,
            booked_seq=current.booked_seq,
            artifact_digest=current.artifact_digest,
            source_run_id=current.source_run_id,
            stage=to_stage,
            digest=new_digest,
        )


def main() -> None:
    reg = MLModelRegistry()
    seq = 0

    def nxt() -> int:
        nonlocal seq
        seq += 1
        return seq

    model = reg.register("fraud-detector", nxt(), run_id="run-1", source="s3://bucket/artifacts")
    assert model.verify()
    digest = "sha256:" + "ab" * 32
    v1 = reg.version("fraud-detector", nxt(), artifact_digest=digest, source_run_id="run-1")
    assert v1.verify() and v1.version == 1 and v1.stage == STAGE_UNSTAGED
    v2 = reg.version("fraud-detector", nxt(), artifact_digest="sha256:" + "cd" * 32)
    assert v2.version == 2
    st = reg.stage("fraud-detector", 1, STAGE_STAGING, nxt())
    assert st.verify() and st.from_stage == STAGE_UNSTAGED and st.to_stage == STAGE_STAGING
    st = reg.stage("fraud-detector", 1, STAGE_PRODUCTION, nxt())
    assert reg.production_version("fraud-detector") == 1
    st = reg.stage("fraud-detector", 2, STAGE_STAGING, nxt())
    st = reg.stage("fraud-detector", 2, STAGE_PRODUCTION, nxt(), archive_existing=True)
    assert reg.production_version("fraud-detector") == 2
    assert reg.version_record("fraud-detector", 1).stage == STAGE_ARCHIVED
    # duplicate registration fails closed
    try:
        reg.register("fraud-detector", nxt())
        raise AssertionError("duplicate register must fail")
    except DuplicateModelError:
        pass
    # illegal move fails closed
    try:
        reg.stage("fraud-detector", 2, STAGE_STAGING, nxt())
        raise AssertionError("Production -> Staging must fail")
    except StageConflictError:
        pass
    # audit has no banned keys
    for row in reg.audit_log():
        for banned in ("payload", "value", "raw", "metadata", "bytes"):
            assert banned not in row, banned
    print("ml-model-registry OK: register, version, stage, transitions, audit")


if __name__ == "__main__":
    main()
