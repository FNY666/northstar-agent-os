"""Docker interface: container lifecycle bookkeeping (build / run / stop).

Research note: *containers* package a process with its filesystem and
dependency set so that "works on my machine" becomes "works anywhere the
daemon runs". The Docker model (Docker, Inc., 2013) has three load-bearing
ideas: (1) *images* are content-addressed layer stacks (a Dockerfile is a
build recipe; the same recipe + base layers deterministically names the same
image); (2) *containers* are ephemeral, writable instances of an image —
configuration (env, ports, volumes) is declared at creation time, and the
container record pins what was declared; (3) *lifecycle* is a small state
machine (created → running → stopped → removed) and transitions are events
that should be auditable.

This module implements that shape as a deterministic, single-host ledger:

* **Image registry** — :meth:`DockerInterface.build` pins an image id
  (``sha256:`` digest) over (name, tag, sorted base layers, sorted build
  args). Rebuilding the same (name, tag) with a *different* recipe refuses
  fail-closed (the id is the contract; silently repointing it would be a
  supply-chain substitution); rebuilding with the *same* recipe is idempotent
  and returns the existing record.
* **Container lifecycle** — :meth:`DockerInterface.run` starts a container
  from a known image id (unknown id → fail-closed, never "latest magic");
  :meth:`DockerInterface.stop` moves it to stopped; :meth:`DockerInterface.remove`
  drops it. State transitions are guarded: double-start, stop-of-stopped,
  and remove-of-running are all refused fail-closed rather than silently
  absorbed.
* **Deterministic** — container ids are minted ``c-<n>``; every caller int
  ``seq`` must strictly increase per interface instance; no wall-clock, no
  randomness, no daemon, no network. Identical call sequences replay to
  identical records, so tests and audits are exact.
* **Fail-closed** — empty/non-str names and tags, bool/negative seqs,
  unknown images, and illegal transitions raise a subclass of
  :class:`DockerError` (a ``DockerError`` hierarchy, never ``None`` or a
  silent default).

Honest scope: this is a *lifecycle ledger*, not a container runtime. It
cannot execute a process, enforce namespaces/cgroups, build a real image,
pull from a registry, or prove that isolation held. The image digest pins
*host-reported* build inputs — a host that lies about layers gets a
consistent ledger of lies (GIGO, same boundary as every other bookkeeping
module). "Container is running" means "the interface recorded a run event
and no later stop", never "a real process is executing". For real
isolation guarantees pair with attestation (see ``remote_attestation``).

Version pin: docker-interface.v1
Schema pin: northstar.docker-interface.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Module version.
DOCKER_INTERFACE_VERSION = "docker-interface.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.docker-interface.v1"

#: Container states.
STATE_CREATED = "created"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"

_ALL_STATES = (STATE_CREATED, STATE_RUNNING, STATE_STOPPED)


class DockerError(Exception):
    """Base error for the docker-interface contract."""


class UnknownImageError(DockerError):
    """A run referenced an image id the registry never built."""


class DuplicateImageError(DockerError):
    """A (name, tag) was rebuilt with a different recipe."""


class UnknownContainerError(DockerError):
    """A container id names nothing known to the lifecycle ledger."""


class IllegalTransitionError(DockerError):
    """A lifecycle transition was refused (already in that state, etc.)."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise DockerError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise DockerError(f"seq must be >= 0, got {seq}")
    return seq


def _check_str(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DockerError(f"{name} must be a non-empty str")
    return value


def _digest(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


def _canonical_mapping(mapping: Mapping[str, str]) -> str:
    """Deterministic serialization of a str->str mapping."""
    items = sorted(mapping.items())
    return "|".join(f"{k}={v}" for k, v in items)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageRecord:
    """A built image: name:tag pinned to a content digest."""

    image_id: str
    name: str
    tag: str
    layers: Tuple[str, ...]
    build_args: Tuple[Tuple[str, str], ...]
    digest: str
    seq: int
    version: str = DOCKER_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "name": self.name,
            "tag": self.tag,
            "layers": list(self.layers),
            "build_args": [list(kv) for kv in self.build_args],
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ContainerRecord:
    """A container created from a pinned image."""

    container_id: str
    image_id: str
    state: str
    name: Optional[str]
    env: Tuple[Tuple[str, str], ...]
    ports: Tuple[Tuple[str, str], ...]
    volumes: Tuple[Tuple[str, str], ...]
    command: Tuple[str, ...]
    digest: str
    seq: int
    version: str = DOCKER_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "container_id": self.container_id,
            "image_id": self.image_id,
            "state": self.state,
            "name": self.name,
            "env": [list(kv) for kv in self.env],
            "ports": [list(kv) for kv in self.ports],
            "volumes": [list(kv) for kv in self.volumes],
            "command": list(self.command),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class StopRecord:
    """A stopped container: terminal state of a lifecycle ledger entry."""

    container_id: str
    previous_state: str
    digest: str
    seq: int
    version: str = DOCKER_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "container_id": self.container_id,
            "previous_state": self.previous_state,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class StartRecord:
    """A created/running transition record."""

    container_id: str
    image_id: str
    previous_state: str
    new_state: str
    digest: str
    seq: int
    version: str = DOCKER_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "container_id": self.container_id,
            "image_id": self.image_id,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------


class DockerInterface:
    """Deterministic container-lifecycle ledger (simulated, no daemon)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: Dict[str, ImageRecord] = {}
        self._by_name_tag: Dict[Tuple[str, str], str] = {}
        self._containers: Dict[str, ContainerRecord] = {}
        self._next_container = 1
        self._last_seq = -1

    # -- internals ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise DockerError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    # -- images ------------------------------------------------------------

    def build(
        self,
        name: str,
        tag: str = "latest",
        seq: int = 0,
        *,
        layers: Sequence[str] = (),
        build_args: Mapping[str, str] = {},
    ) -> ImageRecord:
        """Pin an image id over (name, tag, layers, build_args).

        Rebuilding the same recipe is idempotent; rebuilding the same
        (name, tag) with a *different* recipe raises ``DuplicateImageError``.
        """
        seq = self._claim_seq(seq)
        name = _check_str(name, "name")
        tag = _check_str(tag, "tag")
        if not isinstance(build_args, Mapping):
            raise DockerError("build_args must be a mapping of str->str")
        for k, v in build_args.items():
            if not isinstance(k, str) or not k or not isinstance(v, str):
                raise DockerError("build_args keys/values must be non-empty strs")
        layers_t = tuple(layers)
        for layer in layers_t:
            if not isinstance(layer, str) or not layer:
                raise DockerError("layers must be non-empty strs")
        args_t = tuple(sorted(build_args.items()))

        image_id = _digest(name, tag, _canonical_mapping(dict(args_t)), *layers_t)
        with self._lock:
            key = (name, tag)
            existing_id = self._by_name_tag.get(key)
            if existing_id is not None:
                if existing_id != image_id:
                    raise DuplicateImageError(
                        f"{name}:{tag} already pinned to {existing_id}; "
                        "rebuilding with a different recipe is refused"
                    )
                return self._images[existing_id]
            record = ImageRecord(
                image_id=image_id,
                name=name,
                tag=tag,
                layers=layers_t,
                build_args=args_t,
                digest=image_id,
                seq=seq,
            )
            self._images[image_id] = record
            self._by_name_tag[key] = image_id
            return record

    def image(self, image_id: str) -> ImageRecord:
        """Look up a built image by id (fail-closed on unknown)."""
        image_id = _check_str(image_id, "image_id")
        with self._lock:
            try:
                return self._images[image_id]
            except KeyError:
                raise UnknownImageError(f"unknown image id {image_id!r}") from None

    def images(self) -> Tuple[ImageRecord, ...]:
        """All built images, sorted by image id (deterministic)."""
        with self._lock:
            return tuple(sorted(self._images.values(), key=lambda r: r.image_id))

    # -- containers --------------------------------------------------------

    def run(
        self,
        image_id: str,
        seq: int,
        *,
        name: Optional[str] = None,
        env: Mapping[str, str] = {},
        ports: Mapping[str, str] = {},
        volumes: Mapping[str, str] = {},
        command: Sequence[str] = (),
    ) -> StartRecord:
        """Create a container from a known image id (starts in RUNNING)."""
        seq = self._claim_seq(seq)
        _check_str(image_id, "image_id")
        with self._lock:
            if image_id not in self._images:
                raise UnknownImageError(f"unknown image id {image_id!r}")

        def _norm_strmap(m: Mapping[str, str], label: str) -> Tuple[Tuple[str, str], ...]:
            if not isinstance(m, Mapping):
                raise DockerError(f"{label} must be a mapping of str->str")
            for k, v in m.items():
                if not isinstance(k, str) or not k or not isinstance(v, str):
                    raise DockerError(f"{label} keys/values must be non-empty strs")
            return tuple(sorted(m.items()))

        if name is not None:
            _check_str(name, "name")
        env_t = _norm_strmap(env, "env")
        ports_t = _norm_strmap(ports, "ports")
        volumes_t = _norm_strmap(volumes, "volumes")
        command_t = tuple(command)
        for part in command_t:
            if not isinstance(part, str):
                raise DockerError("command parts must be strs")

        with self._lock:
            container_id = f"c-{self._next_container}"
            self._next_container += 1
            digest = _digest(
                container_id,
                image_id,
                STATE_RUNNING,
                _canonical_mapping(dict(env_t)),
                _canonical_mapping(dict(ports_t)),
                _canonical_mapping(dict(volumes_t)),
                "|".join(command_t),
            )
            record = ContainerRecord(
                container_id=container_id,
                image_id=image_id,
                state=STATE_RUNNING,
                name=name,
                env=env_t,
                ports=ports_t,
                volumes=volumes_t,
                command=command_t,
                digest=digest,
                seq=seq,
            )
            self._containers[container_id] = record
            return StartRecord(
                container_id=container_id,
                image_id=image_id,
                previous_state="absent",
                new_state=STATE_RUNNING,
                digest=digest,
                seq=seq,
            )

    def stop(self, container_id: str, seq: int) -> StopRecord:
        """Move a running container to STOPPED (refused if already stopped)."""
        seq = self._claim_seq(seq)
        _check_str(container_id, "container_id")
        with self._lock:
            record = self._containers.get(container_id)
            if record is None:
                raise UnknownContainerError(f"unknown container {container_id!r}")
            if record.state != STATE_RUNNING:
                raise IllegalTransitionError(
                    f"container {container_id} is {record.state}, not running"
                )
            updated = ContainerRecord(
                container_id=record.container_id,
                image_id=record.image_id,
                state=STATE_STOPPED,
                name=record.name,
                env=record.env,
                ports=record.ports,
                volumes=record.volumes,
                command=record.command,
                digest=_digest(container_id, STATE_RUNNING, STATE_STOPPED),
                seq=seq,
            )
            self._containers[container_id] = updated
            return StopRecord(
                container_id=container_id,
                previous_state=STATE_RUNNING,
                digest=updated.digest,
                seq=seq,
            )

    def remove(self, container_id: str, seq: int) -> str:
        """Drop a stopped container from the ledger (running -> refused)."""
        seq = self._claim_seq(seq)
        _check_str(container_id, "container_id")
        with self._lock:
            record = self._containers.get(container_id)
            if record is None:
                raise UnknownContainerError(f"unknown container {container_id!r}")
            if record.state == STATE_RUNNING:
                raise IllegalTransitionError(
                    f"container {container_id} is running; stop it before removal"
                )
            del self._containers[container_id]
            return container_id

    def container(self, container_id: str) -> ContainerRecord:
        """Current ledger record for a container (fail-closed on unknown)."""
        _check_str(container_id, "container_id")
        with self._lock:
            try:
                return self._containers[container_id]
            except KeyError:
                raise UnknownContainerError(f"unknown container {container_id!r}") from None

    def containers(self, state: Optional[str] = None) -> Tuple[ContainerRecord, ...]:
        """Containers, optionally filtered by state, sorted by id."""
        if state is not None and state not in _ALL_STATES:
            raise DockerError(f"unknown state {state!r}")
        with self._lock:
            records = list(self._containers.values())
        if state is not None:
            records = [r for r in records if r.state == state]
        return tuple(sorted(records, key=lambda r: r.container_id))


# ---------------------------------------------------------------------------
# Audit event shaper
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("image-built", "container-run", "container-stopped", "container-removed")


def docker_interface_audit_event(kind: str, seq: int, **fields: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1``-compatible audit record."""
    if kind not in _AUDIT_KINDS:
        raise DockerError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    return {
        "kind": "audit.ndjson/1",
        "module": "docker-interface",
        "version": DOCKER_INTERFACE_VERSION,
        "schema": SCHEMA_PIN,
        "event": kind,
        "seq": seq,
        "fields": dict(fields),
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    di = DockerInterface()
    img = di.build("app", "v1", seq=1, layers=["base", "deps"])
    same = di.build("app", "v1", seq=2, layers=["base", "deps"])
    assert same.image_id == img.image_id  # idempotent rebuild
    try:
        di.build("app", "v1", seq=3, layers=["base", "evil"])
        raise AssertionError("different recipe must be refused")
    except DuplicateImageError:
        pass
    start = di.run(img.image_id, seq=4, env={"PORT": "8080"})
    assert di.container(start.container_id).state == STATE_RUNNING
    stop = di.stop(start.container_id, seq=5)
    assert stop.previous_state == STATE_RUNNING
    assert di.container(start.container_id).state == STATE_STOPPED
    try:
        di.stop(start.container_id, seq=6)
        raise AssertionError("double stop must be refused")
    except IllegalTransitionError:
        pass
    assert di.remove(start.container_id, seq=7) == start.container_id
    try:
        di.container(start.container_id)
        raise AssertionError("removed container must be gone")
    except UnknownContainerError:
        pass
    try:
        di.run("sha256:deadbeef", seq=8)
        raise AssertionError("unknown image must be refused")
    except UnknownImageError:
        pass
    ev = docker_interface_audit_event("image-built", 9, image_id=img.image_id)
    assert ev["module"] == "docker-interface"
    print("docker-interface OK: build, run, stop, remove, refusals")


if __name__ == "__main__":
    main()
