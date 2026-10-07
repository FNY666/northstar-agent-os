"""Artifact publisher: PyPI-style build/upload/yank bookkeeping (simulated).

Research note: publishing an artifact to a package index (PyPI,
npm, Maven Central) is a three-stage contract:

* **build** — source becomes a distributable artifact (sdist, wheel,
  tarball). The build is pinned: (name, version, build-type,
  filename) plus a ``sha256:`` digest over the canonical plan. The
  build backend is named but not executed here.
* **upload** — the artifact is admitted to the index. PyPI-style
  indexes are *immutable*: once a (project, version, filename) is
  uploaded, re-uploading the same file is refused. A second upload of
  the same build raises; a new build (e.g. a re-spun sdist) needs a
  fresh build id, exactly like rebuilding with a different hash.
* **yank** — the artifact stays on the index but installs fail unless
  explicitly pinned (PEP 592). Yank is terminal: there is no
  un-yank, because yank is a signal to installers, and the signal
  must not flap.

Every record is frozen, digest-pinned, and minted on
caller-supplied strictly-increasing int seqs (no wall-clock). The
uploader is host-injectable: ``uploader(upload_record) -> bool``.
The default uploader accepts in memory so tests run with no network.

Honest scope: this books *publish decisions*, not releases — an
``uploaded`` build means "the host uploader reported success", never
"the index actually serves it"; ``build()`` pins the host-reported
build plan, never proves the bytes match; pair with ``sbom_generator``
for content claims and ``sign`` with a real key for distribution
trust. Nothing here touches a network.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
ARTIFACT_PUBLISHER_VERSION = "artifact-publisher.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.artifact-publisher.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "distribution-registered",
    "built",
    "uploaded",
    "yanked",
    "rejected",
)

#: Pinned build-type vocabulary (sdist / wheel, the PyPI pair).
_BUILD_TYPES = ("sdist", "wheel")

#: Hard cap on a metadata blob (guardrail against a runaway host).
_MAX_META_BYTES = 256 * 1024

#: PEP 440-ish version shape (public versions; no local segments).
_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*"
    r"((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?$"
)

#: Distribution name shape (PEP 508 name rules).
_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")


class ArtifactPublisherError(Exception):
    """Base error for the artifact publisher."""


class ValidationError(ArtifactPublisherError):
    """Raised for malformed names, versions, build types, or metadata."""


class UnknownDistributionError(ArtifactPublisherError):
    """Raised when referencing an unregistered distribution."""


class DuplicateDistributionError(ArtifactPublisherError):
    """Raised when registering an already-known (name, version)."""


class UnknownBuildError(ArtifactPublisherError):
    """Raised when referencing an unknown build id."""


class DuplicateBuildError(ArtifactPublisherError):
    """Raised when a distribution already has this build type."""


class AlreadyPublishedError(ArtifactPublisherError):
    """Raised on re-upload of an already-uploaded build (immutability)."""


class TerminalYankError(ArtifactPublisherError):
    """Raised when mutating a yanked build (yank is terminal)."""


class SeqOrderError(ArtifactPublisherError):
    """Raised when a caller-supplied seq is not strictly increasing."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be non-negative")
    return value


def _canonicalize(obj: Any) -> Any:
    """Canonicalize a payload; fail closed on anything unrepresentable."""
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        if abs(obj) > 2 ** 53:
            raise ValidationError("int magnitude beyond 2**53 refused (JCS float-loss caveat)")
        return obj
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValidationError("NaN/inf refused")
        if obj.is_integer() and abs(obj) > 2 ** 53:
            raise ValidationError("integral float magnitude beyond 2**53 refused")
        return obj
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    if isinstance(obj, Mapping):
        for k in obj:
            if not isinstance(k, str) or not k:
                raise ValidationError(f"bad mapping key {k!r}")
        return {k: _canonicalize(obj[k]) for k in sorted(obj)}
    raise ValidationError(f"non-canonicalizable value of type {type(obj).__name__}")


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _normalize_name(name: Any) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapsed to '-'."""
    if not isinstance(name, str) or not name:
        raise ValidationError(f"name must be a non-empty str, got {name!r}")
    if not _NAME_RE.match(name):
        raise ValidationError(f"bad distribution name {name!r}")
    return re.sub(r"[-_.]+", "-", name).lower()


def _check_version(version: Any) -> str:
    if not isinstance(version, str) or not version:
        raise ValidationError(f"version must be a non-empty str, got {version!r}")
    if not _VERSION_RE.match(version):
        raise ValidationError(f"bad PEP 440-ish version {version!r}")
    return version


@dataclass(frozen=True)
class DistributionRecord:
    """One registered (name, version) distribution plan."""

    dist_id: str
    name: str
    normalized_name: str
    dist_version: str
    seq: int
    digest: str
    module_version: str = ARTIFACT_PUBLISHER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "dist_id": self.dist_id,
            "name": self.name,
            "normalized_name": self.normalized_name,
            "version": self.dist_version,
            "seq": self.seq,
            "digest": self.digest,
            "module_version": self.module_version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin."""
        body = {
            "dist_id": self.dist_id,
            "name": self.name,
            "normalized_name": self.normalized_name,
            "version": self.dist_version,
            "seq": self.seq,
            "module_version": self.module_version,
        }
        return _digest(body) == self.digest


@dataclass(frozen=True)
class BuildRecord:
    """One built artifact (sdist or wheel) with its planned filename."""

    build_id: str
    dist_id: str
    build_type: str
    filename: str
    digest: str
    seq: int
    version: str = ARTIFACT_PUBLISHER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "build_id": self.build_id,
            "dist_id": self.dist_id,
            "build_type": self.build_type,
            "filename": self.filename,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        body = {
            "build_id": self.build_id,
            "dist_id": self.dist_id,
            "build_type": self.build_type,
            "filename": self.filename,
            "seq": self.seq,
            "module_version": self.version,
        }
        return _digest(body) == self.digest


@dataclass(frozen=True)
class UploadRecord:
    """Receipt for one successful index admission (immutable from here)."""

    upload_id: str
    build_id: str
    uploader: str
    build_digest: str
    seq: int
    digest: str
    version: str = ARTIFACT_PUBLISHER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "upload_id": self.upload_id,
            "build_id": self.build_id,
            "uploader": self.uploader,
            "build_digest": self.build_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        body = {
            "upload_id": self.upload_id,
            "build_id": self.build_id,
            "uploader": self.uploader,
            "build_digest": self.build_digest,
            "seq": self.seq,
            "module_version": self.version,
        }
        return _digest(body) == self.digest


@dataclass(frozen=True)
class YankRecord:
    """Terminal yank marker for one build (PEP 592 discipline)."""

    build_id: str
    reason: str
    seq: int
    version: str = ARTIFACT_PUBLISHER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "build_id": self.build_id,
            "reason": self.reason,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


class ArtifactPublisher:
    """Publish-ledger for PyPI-style distributions (simulated).

    ``register(distribution_id, name, version, seq)`` opens the ledger
    for one (name, version). ``build(...)`` pins one artifact file per
    build type. ``upload(...)`` admits a build to the (simulated)
    index — immutable afterwards. ``yank(...)`` marks a build yanked,
    terminal. ``uploader(build_record) -> bool`` is host-injectable;
    the default accepts in memory.
    """

    def __init__(self, uploader: Callable[[BuildRecord], bool] | None = None) -> None:
        if uploader is not None and not callable(uploader):
            raise ValidationError("uploader must be callable")
        self._uploader: Callable[[BuildRecord], bool] = uploader or (lambda _b: True)
        self._lock = threading.RLock()
        self._dists: dict[str, DistributionRecord] = {}
        self._dist_keys: set[tuple[str, str]] = set()
        self._dist_seq = 0
        self._builds: dict[str, BuildRecord] = {}
        self._dist_build_types: dict[str, set[str]] = {}
        self._build_seq = 0
        self._uploads: dict[str, UploadRecord] = {}
        self._upload_seq = 0
        self._yanks: dict[str, YankRecord] = {}
        self._last_seq = -1
        self._audit_log: list[dict[str, Any]] = []

    def _monotonic(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} must strictly increase (last {self._last_seq})")
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            artifact_publisher_audit_event(kind, seq, **detail)
        )

    # -- distribution ----------------------------------------------------

    def register(self, distribution_id: Any, name: Any, version: Any,
                 seq: Any) -> DistributionRecord:
        """Register a (name, version) distribution plan."""
        with self._lock:
            seq = self._monotonic(seq)  # failed mutation consumes seq
            if not isinstance(distribution_id, str) or not distribution_id:
                raise ValidationError(f"distribution_id must be a non-empty str, got {distribution_id!r}")
            if distribution_id in self._dists:
                raise DuplicateDistributionError(f"distribution {distribution_id!r} already registered")
            normalized = _normalize_name(name)
            ver = _check_version(version)
            key = (normalized, ver)
            if key in self._dist_keys:
                raise DuplicateDistributionError(
                    f"(name, version) ({normalized!r}, {ver!r}) already registered")
            self._dist_seq += 1
            body = {
                "dist_id": distribution_id,
                "name": name,
                "normalized_name": normalized,
                "version": ver,
                "seq": seq,
                "module_version": ARTIFACT_PUBLISHER_VERSION,
            }
            rec = DistributionRecord(
                dist_id=distribution_id,
                name=name,
                normalized_name=normalized,
                dist_version=ver,
                seq=seq,
                digest=_digest(body),
            )
            self._dists[distribution_id] = rec
            self._dist_keys.add(key)
            self._dist_build_types[distribution_id] = set()
            self._emit("distribution-registered", seq, dist_id=distribution_id)
            return rec

    # -- build ------------------------------------------------------------

    @staticmethod
    def _filename(normalized_name: str, version: str, build_type: str) -> str:
        if build_type == "sdist":
            return f"{normalized_name}-{version}.tar.gz"
        return f"{normalized_name}-{version}-py3-none-any.whl"

    def build(self, distribution_id: Any, seq: Any,
              build_type: str = "sdist",
              metadata: Mapping[str, Any] | None = None) -> BuildRecord:
        """Build one artifact for a registered distribution (simulated)."""
        with self._lock:
            seq = self._monotonic(seq)
            dist = self._dists.get(distribution_id) if isinstance(distribution_id, str) else None
            if dist is None:
                raise UnknownDistributionError(f"unknown distribution {distribution_id!r}")
            if build_type not in _BUILD_TYPES:
                raise ValidationError(f"unknown build type {build_type!r}")
            if build_type in self._dist_build_types[distribution_id]:
                raise DuplicateBuildError(
                    f"distribution {distribution_id!r} already built {build_type!r}")
            meta = _canonicalize(dict(metadata or {}))
            if len(jcs_canonical_json(meta)) > _MAX_META_BYTES:
                raise ValidationError("metadata exceeds 256 KiB guardrail")
            self._build_seq += 1
            build_id = f"bld-{self._build_seq}"
            filename = self._filename(dist.normalized_name, dist.dist_version, build_type)
            body = {
                "build_id": build_id,
                "dist_id": distribution_id,
                "build_type": build_type,
                "filename": filename,
                "seq": seq,
                "module_version": ARTIFACT_PUBLISHER_VERSION,
            }
            rec = BuildRecord(
                build_id=build_id,
                dist_id=distribution_id,
                build_type=build_type,
                filename=filename,
                digest=_digest(body),
                seq=seq,
            )
            self._builds[build_id] = rec
            self._dist_build_types[distribution_id].add(build_type)
            self._emit("built", seq, build_id=build_id)
            return rec

    # -- upload -----------------------------------------------------------

    def upload(self, build_id: Any, seq: Any, uploader: str = "host") -> UploadRecord:
        """Admit a build to the (simulated) index; immutable afterwards."""
        with self._lock:
            seq = self._monotonic(seq)
            build = self._builds.get(build_id) if isinstance(build_id, str) else None
            if build is None:
                raise UnknownBuildError(f"unknown build {build_id!r}")
            if build_id in self._yanks:
                raise TerminalYankError(f"build {build_id!r} is yanked; upload refused")
            if build_id in self._uploads:
                raise AlreadyPublishedError(f"build {build_id!r} already uploaded (immutable)")
            if not isinstance(uploader, str) or not uploader:
                raise ValidationError(f"uploader must be a non-empty str, got {uploader!r}")
            if not bool(self._uploader(build)):
                raise ArtifactPublisherError("host uploader reported failure; build not admitted")
            self._upload_seq += 1
            upload_id = f"upl-{self._upload_seq}"
            body = {
                "upload_id": upload_id,
                "build_id": build_id,
                "uploader": uploader,
                "build_digest": build.digest,
                "seq": seq,
                "module_version": ARTIFACT_PUBLISHER_VERSION,
            }
            rec = UploadRecord(
                upload_id=upload_id,
                build_id=build_id,
                uploader=uploader,
                build_digest=build.digest,
                seq=seq,
                digest=_digest(body),
            )
            # verify() parity: the body above must re-derive the digest we pin
            assert rec.verify(), "digest pin mismatch"
            self._uploads[build_id] = rec
            self._emit("uploaded", seq, build_id=build_id)
            return rec

    # -- yank --------------------------------------------------------------

    def yank(self, build_id: Any, reason: Any, seq: Any) -> YankRecord:
        """Yank a build: stays on the index, installs fail unless pinned. Terminal."""
        with self._lock:
            seq = self._monotonic(seq)
            if build_id not in self._builds:
                raise UnknownBuildError(f"unknown build {build_id!r}")
            if build_id in self._yanks:
                raise TerminalYankError(f"build {build_id!r} already yanked (terminal)")
            if not isinstance(reason, str) or not reason.strip():
                raise ValidationError("yank reason must be a non-empty str")
            rec = YankRecord(build_id=build_id, reason=reason.strip(), seq=seq)
            self._yanks[build_id] = rec
            self._emit("yanked", seq, build_id=build_id)
            return rec

    # -- views --------------------------------------------------------------

    def status(self, build_id: Any) -> str:
        """One of: 'built', 'uploaded', 'yanked'."""
        if build_id in self._yanks:
            return "yanked"
        if build_id in self._uploads:
            return "uploaded"
        if build_id in self._builds:
            return "built"
        raise UnknownBuildError(f"unknown build {build_id!r}")

    def get_build(self, build_id: Any) -> BuildRecord:
        """Read back one build record."""
        if build_id not in self._builds:
            raise UnknownBuildError(f"unknown build {build_id!r}")
        return self._builds[build_id]

    def get_distribution(self, distribution_id: Any) -> DistributionRecord:
        """Read back one distribution record."""
        if distribution_id not in self._dists:
            raise UnknownDistributionError(f"unknown distribution {distribution_id!r}")
        return self._dists[distribution_id]

    def upload_record(self, build_id: Any) -> UploadRecord:
        """Read back one upload receipt."""
        if build_id not in self._uploads:
            raise UnknownBuildError(f"no upload for build {build_id!r}")
        return self._uploads[build_id]

    def yank_record(self, build_id: Any) -> YankRecord:
        """Read back one yank marker."""
        if build_id not in self._yanks:
            raise UnknownBuildError(f"no yank for build {build_id!r}")
        return self._yanks[build_id]

    def builds_of(self, distribution_id: Any) -> tuple[BuildRecord, ...]:
        """All builds for one distribution, oldest first."""
        if distribution_id not in self._dists:
            raise UnknownDistributionError(f"unknown distribution {distribution_id!r}")
        out = [b for b in self._builds.values() if b.dist_id == distribution_id]
        return tuple(sorted(out, key=lambda b: b.seq))

    def stats(self) -> dict[str, int]:
        """Ledger counts per state."""
        with self._lock:
            return {
                "distributions": len(self._dists),
                "builds": len(self._builds),
                "uploaded": len(self._uploads),
                "yanked": len(self._yanks),
            }

    def audit_log(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def artifact_publisher_audit_event(kind: str, seq: int, **detail: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for publisher activity."""
    if kind not in _AUDIT_KINDS:
        raise ArtifactPublisherError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": ARTIFACT_PUBLISHER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    event.update({k: _canonicalize(v) for k, v in detail.items()})
    return event


def main() -> None:
    """Self-check: register, build, upload, yank, refusals."""
    pub = ArtifactPublisher()
    d = pub.register("d1", "northstar-Agent", "0.3.dev0", 0)
    assert d.verify() and d.normalized_name == "northstar-agent"
    b1 = pub.build("d1", 1)
    assert b1.filename == "northstar-agent-0.3.dev0.tar.gz"
    assert b1.verify()
    b2 = pub.build("d1", 2, build_type="wheel")
    assert b2.filename.endswith(".whl")
    u = pub.upload(b1.build_id, 3)
    assert u.verify() and pub.status(b1.build_id) == "uploaded"
    y = pub.yank(b2.build_id, "broken wheel metadata", 4)
    assert y.reason and pub.status(b2.build_id) == "yanked"
    try:
        pub.upload(b1.build_id, 5)
    except AlreadyPublishedError:
        pass
    else:
        raise AssertionError("re-upload must refuse")
    print("artifact-publisher OK: register, build, upload, yank, refusals")


if __name__ == "__main__":
    main()
