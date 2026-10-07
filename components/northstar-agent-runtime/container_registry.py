"""Container registry: OCI distribution-spec-shaped image bookkeeping.

A container registry answers "which manifest (and which blobs) does
``repo:tag`` resolve to?" -- the bookkeeping half of image lifecycle
governance, shaped after the OCI Distribution Spec and the Image
Manifest Spec:

* :meth:`ContainerRegistry.push_blob` records a content-addressed blob
  by its ``sha256:`` digest. Blobs are *pinned*, never overwritten: a
  digest names bytes forever. The registry pins digests, it never stores
  blob bytes (the host owns artifact storage).
* :meth:`ContainerRegistry.push` records a manifest (config + layer
  digest list) under a repository. The manifest's own ``sha256:`` digest
  is computed by the registry -- the host cannot name its own digest.
* :meth:`ContainerRegistry.tag` binds a human-readable tag
  (``repo:tag``) to a manifest digest. Tags are mutable -- re-tagging is
  recorded as a ``TagMove`` so history is never silently rewritten.
* :meth:`ContainerRegistry.pull` resolves a tag *or* a digest reference
  to the frozen manifest record, with fail-closed resolution (unknown
  repository, unknown tag, unknown digest, dangling tag).
* :meth:`ContainerRegistry.untag` removes a tag binding without
  touching the pinned manifest (digests are immutable; only names are
  mutable).
* Garbage-collection views: :meth:`ContainerRegistry.unreferenced_blobs`
  and :meth:`ContainerRegistry.unreferenced_manifests` answer "which
  pins nothing points at anymore" so a host GC pass can be audited
  against them.

Honest scope: the registry pins what the host *reported*. It cannot
prove the blob bytes match the digest the host uploaded (the host holds
both), cannot verify signatures or provenance attestations (see
``remote_attestation`` for a hardware-anchored story), and cannot prove
a manifest's layer list is complete or correct. A ``pull`` resolves
"what this registry recorded for this name", never "this image is safe
to run". Deterministic, no wall-clock (all caller-supplied int seqs),
stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple


#: Version pin for this module's record shape.
CONTAINER_REGISTRY_VERSION = "container-registry.v1"

#: Schema pin carried on audit records.
CONTAINER_REGISTRY_SCHEMA = "northstar.container-registry.v1"

#: Largest integer exactly representable in a JSON float (same
#: canonicalization caveat as the rest of the batch line; all pins here
#: are hex digests, never raw ints, so it does not apply to pins --
#: manifest *fields* are still validated).
_MAX_SAFE_INTEGER = 2**53

#: OCI digest shape: ``sha256:<64 hex>``.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Repository name shape (OCI): lowercase alphanumerics with ``/``,
#: ``.``, ``_``, ``-`` separators for namespaces.
_REPOSITORY_RE = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")

#: Tag shape: word-ish, up to 128 chars.
_TAG_RE = re.compile(r"^[\w][\w.\-]{0,127}$")


class ContainerRegistryError(Exception):
    """Base error for container-registry failures."""


class UnknownRepositoryError(ContainerRegistryError):
    """The named repository has no pushed manifests."""


class UnknownReferenceError(ContainerRegistryError):
    """A tag or digest reference resolves to nothing in this repository."""


class DigestMismatchError(ContainerRegistryError):
    """A claimed digest does not match the recomputed manifest digest."""


class DanglingTagError(ContainerRegistryError):
    """A tag points at a manifest digest that is no longer recorded."""


class DuplicateBlobError(ContainerRegistryError):
    """A blob with the same digest was recorded with different metadata."""


def _pin_bytes(payload: bytes) -> str:
    """Return a ``sha256:`` pin of raw bytes."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> str:
    """Canonical JSON with exact int handling (fail-closed on NaN/inf
    and on integral floats beyond 2**53, same caveat as the batch line)."""

    def _check(v: Any) -> None:
        if isinstance(v, bool):
            return
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ContainerRegistryError(
                    "NaN/inf manifest field is not canonicalizable"
                )
            if v.is_integer() and abs(v) > _MAX_SAFE_INTEGER:
                raise ContainerRegistryError(
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
                    raise ContainerRegistryError("manifest keys must be str")
                _check(item)

    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ContainerRegistryError("seq must be an int")
    if seq < 0:
        raise ContainerRegistryError("seq must be >= 0")
    return seq


def _check_digest(digest: Any) -> str:
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise ContainerRegistryError(
            "digest must look like 'sha256:<64 lowercase hex>'"
        )
    return digest


def _check_repository(repository: Any) -> str:
    if not isinstance(repository, str) or not _REPOSITORY_RE.match(repository):
        raise ContainerRegistryError("repository must be a lowercase OCI name")
    return repository


def _check_tag(tag: Any) -> str:
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise ContainerRegistryError("tag must be a valid OCI tag")
    return tag


def _check_reference(reference: Any) -> str:
    """A reference is either a tag or a digest."""
    if not isinstance(reference, str):
        raise ContainerRegistryError("reference must be str")
    if _DIGEST_RE.match(reference):
        return reference
    return _check_tag(reference)


@dataclass(frozen=True)
class BlobRecord:
    """A pinned content-addressed blob."""

    digest: str
    size_bytes: int
    media_type: str
    seq: int
    version: str = CONTAINER_REGISTRY_VERSION

    def __post_init__(self) -> None:
        if not _DIGEST_RE.match(self.digest):
            raise ContainerRegistryError("BlobRecord digest must be sha256:<hex>")
        if isinstance(self.size_bytes, bool) or not isinstance(
            self.size_bytes, int
        ):
            raise ContainerRegistryError("BlobRecord size_bytes must be an int")
        if self.size_bytes < 0:
            raise ContainerRegistryError("BlobRecord size_bytes must be >= 0")
        if not self.media_type or not isinstance(self.media_type, str):
            raise ContainerRegistryError("BlobRecord media_type must be non-empty str")
        _check_seq(self.seq)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class ManifestRecord:
    """A pinned manifest bound to a repository."""

    repository: str
    digest: str
    media_type: str
    config_digest: str
    layer_digests: Tuple[str, ...]
    seq: int
    version: str = CONTAINER_REGISTRY_VERSION

    def __post_init__(self) -> None:
        _check_repository(self.repository)
        if not _DIGEST_RE.match(self.digest):
            raise ContainerRegistryError("ManifestRecord digest must be sha256:<hex>")
        if not self.media_type or not isinstance(self.media_type, str):
            raise ContainerRegistryError(
                "ManifestRecord media_type must be non-empty str"
            )
        _check_digest(self.config_digest)
        for layer in self.layer_digests:
            _check_digest(layer)
        _check_seq(self.seq)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "digest": self.digest,
            "media_type": self.media_type,
            "config_digest": self.config_digest,
            "layer_digests": list(self.layer_digests),
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class PullResult:
    """The outcome of resolving a reference to a manifest."""

    repository: str
    reference: str
    digest: str
    manifest: ManifestRecord
    resolved_via: str  # "tag" | "digest"
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "reference": self.reference,
            "digest": self.digest,
            "manifest": self.manifest.as_dict(),
            "resolved_via": self.resolved_via,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class TagMove:
    """An audit record of a tag being (re-)pointed at a digest."""

    repository: str
    tag: str
    old_digest: Optional[str]
    new_digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "tag": self.tag,
            "old_digest": self.old_digest,
            "new_digest": self.new_digest,
            "seq": self.seq,
        }


class ContainerRegistry:
    """OCI-shaped image registry bookkeeping (single-host, in-memory)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blobs: Dict[str, BlobRecord] = {}
        self._manifests: Dict[Tuple[str, str], ManifestRecord] = {}
        self._tags: Dict[Tuple[str, str], str] = {}
        self._tag_moves: Tuple[TagMove, ...] = ()

    # ------------------------------------------------------------------
    # blobs
    # ------------------------------------------------------------------

    def push_blob(
        self, digest: str, size_bytes: int, media_type: str, seq: int
    ) -> BlobRecord:
        """Record a content-addressed blob. A digest is pinned forever:
        re-recording the same digest with different metadata is a
        conflict, never a silent overwrite."""
        _check_digest(digest)
        if not isinstance(media_type, str) or not media_type:
            raise ContainerRegistryError("media_type must be non-empty str")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
            raise ContainerRegistryError("size_bytes must be an int")
        if size_bytes < 0:
            raise ContainerRegistryError("size_bytes must be >= 0")
        _check_seq(seq)
        with self._lock:
            existing = self._blobs.get(digest)
            if existing is not None:
                if (
                    existing.size_bytes != size_bytes
                    or existing.media_type != media_type
                ):
                    raise DuplicateBlobError(
                        "blob digest already recorded with different metadata"
                    )
                return existing
            record = BlobRecord(
                digest=digest,
                size_bytes=size_bytes,
                media_type=media_type,
                seq=seq,
            )
            self._blobs[digest] = record
            return record

    def blob(self, digest: str) -> Optional[BlobRecord]:
        _check_digest(digest)
        with self._lock:
            return self._blobs.get(digest)

    # ------------------------------------------------------------------
    # manifests
    # ------------------------------------------------------------------

    @staticmethod
    def manifest_digest(
        media_type: str, config_digest: str, layer_digests: Tuple[str, ...]
    ) -> str:
        """The registry-computed manifest digest (the host cannot name
        its own digest). Deterministic over the canonical manifest
        body."""
        body = _canonical_json(
            {
                "mediaType": media_type,
                "config": config_digest,
                "layers": list(layer_digests),
            }
        )
        return _pin_bytes(body.encode("utf-8"))

    def push(
        self,
        repository: str,
        media_type: str,
        config_digest: str,
        layer_digests: Tuple[str, ...],
        seq: int,
    ) -> ManifestRecord:
        """Record a manifest under a repository. The registry computes
        the digest; re-pushing identical content is idempotent."""
        _check_repository(repository)
        if not isinstance(media_type, str) or not media_type:
            raise ContainerRegistryError("media_type must be non-empty str")
        _check_digest(config_digest)
        layers = tuple(_check_digest(layer) for layer in layer_digests)
        _check_seq(seq)
        digest = self.manifest_digest(media_type, config_digest, layers)
        with self._lock:
            key = (repository, digest)
            existing = self._manifests.get(key)
            if existing is not None:
                return existing
            record = ManifestRecord(
                repository=repository,
                digest=digest,
                media_type=media_type,
                config_digest=config_digest,
                layer_digests=layers,
                seq=seq,
            )
            self._manifests[key] = record
            return record

    # ------------------------------------------------------------------
    # tags
    # ------------------------------------------------------------------

    def tag(self, repository: str, tag: str, digest: str, seq: int) -> TagMove:
        """Bind ``repository:tag`` to a manifest digest. Tags are
        mutable; every move is recorded."""
        _check_repository(repository)
        _check_tag(tag)
        _check_digest(digest)
        _check_seq(seq)
        with self._lock:
            if (repository, digest) not in self._manifests:
                raise UnknownReferenceError(
                    "cannot tag: manifest digest not recorded in repository"
                )
            key = (repository, tag)
            old = self._tags.get(key)
            move = TagMove(
                repository=repository,
                tag=tag,
                old_digest=old,
                new_digest=digest,
                seq=seq,
            )
            self._tags[key] = digest
            self._tag_moves = self._tag_moves + (move,)
            return move

    def untag(self, repository: str, tag: str, seq: int) -> TagMove:
        """Remove a tag binding. The pinned manifest is untouched."""
        _check_repository(repository)
        _check_tag(tag)
        _check_seq(seq)
        with self._lock:
            key = (repository, tag)
            old = self._tags.get(key)
            if old is None:
                raise UnknownReferenceError("tag is not bound")
            del self._tags[key]
            move = TagMove(
                repository=repository,
                tag=tag,
                old_digest=old,
                new_digest=None,
                seq=seq,
            )
            self._tag_moves = self._tag_moves + (move,)
            return move

    def pull(self, repository: str, reference: str, seq: int) -> PullResult:
        """Resolve a tag or digest reference to its manifest record."""
        _check_repository(repository)
        reference = _check_reference(reference)
        _check_seq(seq)
        with self._lock:
            if reference.startswith("sha256:"):
                record = self._manifests.get((repository, reference))
                if record is None:
                    raise UnknownReferenceError(
                        "digest not recorded in repository"
                    )
                return PullResult(
                    repository=repository,
                    reference=reference,
                    digest=reference,
                    manifest=record,
                    resolved_via="digest",
                    seq=seq,
                )
            digest = self._tags.get((repository, reference))
            if digest is None:
                raise UnknownReferenceError("tag is not bound in repository")
            record = self._manifests.get((repository, digest))
            if record is None:
                raise DanglingTagError(
                    "tag points at a manifest that is no longer recorded"
                )
            return PullResult(
                repository=repository,
                reference=reference,
                digest=digest,
                manifest=record,
                resolved_via="tag",
                seq=seq,
            )

    # ------------------------------------------------------------------
    # views
    # ------------------------------------------------------------------

    def tags(self, repository: str) -> Tuple[str, ...]:
        _check_repository(repository)
        with self._lock:
            return tuple(
                sorted(tag for (repo, tag) in self._tags if repo == repository)
            )

    def tag_history(self) -> Tuple[TagMove, ...]:
        with self._lock:
            return self._tag_moves

    def manifests(self, repository: str) -> Tuple[ManifestRecord, ...]:
        _check_repository(repository)
        with self._lock:
            records = [
                record
                for (repo, _), record in self._manifests.items()
                if repo == repository
            ]
        return tuple(sorted(records, key=lambda r: (r.digest, r.seq)))

    def unreferenced_blobs(self) -> Tuple[BlobRecord, ...]:
        """Blobs pinned by no manifest layer list and not a config --
        candidates a host GC pass could reclaim (audit use only)."""
        with self._lock:
            referenced = set()
            for record in self._manifests.values():
                referenced.add(record.config_digest)
                referenced.update(record.layer_digests)
            orphans = [
                record
                for digest, record in self._blobs.items()
                if digest not in referenced
            ]
        return tuple(sorted(orphans, key=lambda r: r.digest))

    def unreferenced_manifests(self) -> Tuple[ManifestRecord, ...]:
        """Manifests no tag points at (audit use only)."""
        with self._lock:
            referenced = {
                (repo, digest) for (repo, _), digest in self._tags.items()
            }
            orphans = [
                record
                for (repo, digest), record in self._manifests.items()
                if (repo, digest) not in referenced
            ]
        return tuple(sorted(orphans, key=lambda r: (r.repository, r.digest)))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "blobs": len(self._blobs),
                "manifests": len(self._manifests),
                "tags": len(self._tags),
                "tag_moves": len(self._tag_moves),
            }


def container_registry_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for registry operations.

    Fixed kinds: ``blob-pushed``, ``manifest-pushed``, ``tagged``,
    ``untagged``, ``pulled``, ``rejected``. Raw content is never
    carried -- only digests, repository names, and tags.
    """
    _VALID_KINDS = frozenset(
        {
            "blob-pushed",
            "manifest-pushed",
            "tagged",
            "untagged",
            "pulled",
            "rejected",
        }
    )
    if kind not in _VALID_KINDS:
        raise ContainerRegistryError("unknown audit kind: %r" % (kind,))
    _check_seq(seq)
    event = {
        "schema": CONTAINER_REGISTRY_SCHEMA,
        "version": CONTAINER_REGISTRY_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }
    _canonical_json(event)  # validate canonicalizability
    return event


def main() -> None:
    reg = ContainerRegistry()
    config = "sha256:" + "a" * 64
    layer = "sha256:" + "b" * 64
    reg.push_blob(config, 512, "application/vnd.oci.image.config.v1+json", 0)
    reg.push_blob(layer, 1024, "application/vnd.oci.image.layer.v1.tar", 1)
    manifest = reg.push(
        "library/app",
        "application/vnd.oci.image.manifest.v1+json",
        config,
        (layer,),
        2,
    )
    reg.tag("library/app", "latest", manifest.digest, 3)
    pulled = reg.pull("library/app", "latest", 4)
    assert pulled.manifest.digest == manifest.digest
    assert pulled.resolved_via == "tag"
    by_digest = reg.pull("library/app", manifest.digest, 5)
    assert by_digest.resolved_via == "digest"
    print("container-registry OK: push, tag, pull, untag")


if __name__ == "__main__":
    main()
