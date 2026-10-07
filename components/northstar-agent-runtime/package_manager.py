"""Package manager interface: npm-style install/resolve/lock bookkeeping.

Research note: an *agent* needs a package manager the same way a
developer does — to pull a tool definition, a skill pack, or a sandbox
plugin into its environment. The load-bearing invariants are the same
as npm's: (1) *deterministic resolution* — the same registry index and
the same range constraints must always resolve to the same version
tree; (2) *conflict refusal* — two constraints that demand incompatible
versions of one package are a hard error, never a silent pick;
(3) *lock-file integrity* — the lock file pins exact versions, and the
pin is re-derivable so drift is detectable; (4) *cycle refusal* —
dependency cycles are rejected at install time; (5) *uninstall
consistency* — a package another installed package depends on cannot be
removed.

This module implements that shape as a deterministic, single-host
ledger:

* **Registry** — :meth:`PackageManager.register` pins a frozen
  :class:`PackageRecord` (``pkg-<n>`` id) for a (name, version) pair
  with its declared dependency ranges. Versions are semver
  ``MAJOR.MINOR.PATCH``; ranges are ``exact`` / ``^caret`` / ``~tilde``
  / ``*``.
* **Resolution** — :meth:`PackageManager.resolve` walks the dependency
  graph depth-first with a pinned constraint set; each resolved
  (name, version) gets a digest pin. A version that does not satisfy
  *every* recorded constraint for its name raises
  :class:`VersionConflictError` fail-closed; a cycle raises
  :class:`DependencyCycleError`.
* **Install** — :meth:`PackageManager.install` resolves, then pins a
  frozen :class:`InstallReceipt` recording exactly which (name, version)
  pairs were installed, topologically ordered (dependencies before
  dependents).
* **Lock** — :meth:`PackageManager.lock` emits a frozen
  :class:`LockFile` (package-lock.json discipline) over the installed
  tree with a re-derivable ``sha256:`` pin; :meth:`LockFile.verify`
  re-derives it.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock, no RNG — ids are monotonic ``pkg-<n>`` /
``ins-<n>`` / ``lk-<n>`` counters), RLock-guarded, fail-closed (bool/empty
ids, bad semver, bad ranges, unknown packages, unsatisfied ranges,
conflicts, cycles, double-install of the same root, uninstall of a
required package all raise a subclass of :class:`PackageManagerError`),
stdlib-only, type-tagged canonical digest encoding (bool != int; floats
and |n| >= 2**53 refused), audit events shaped for ``audit.ndjson/1``,
``main()`` self-check.

Honest scope: this is a *claims ledger*, not a downloader. It cannot
fetch tarballs, verify a registry signature, or run install scripts —
``register()`` pins what the host *reported* as published. For real
supply-chain security pair with a signed registry
(:class:`sbom_generator`, ``sigstore`` attestation) and install only
from a lock file whose pin verifies.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

VERSION = "package-manager.v1"
SCHEMA = "northstar.package-manager.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "PackageManagerError",
    "UnknownPackageError",
    "DuplicatePackageError",
    "BadVersionError",
    "BadRangeError",
    "NoSatisfyingVersionError",
    "VersionConflictError",
    "DependencyCycleError",
    "AlreadyInstalledError",
    "RequiredByError",
    "RANGE_KINDS",
    "PackageDependency",
    "PackageRecord",
    "ResolvedPackage",
    "ResolutionReport",
    "InstallReceipt",
    "LockEntry",
    "LockFile",
    "PackageManager",
    "package_manager_audit_event",
]

RANGE_KINDS = ("exact", "caret", "tilde", "star")

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class PackageManagerError(Exception):
    """Base for all package-manager errors (fail-closed taxonomy)."""


class UnknownPackageError(PackageManagerError):
    """Package name (or a version of it) is not in the registry."""


class DuplicatePackageError(PackageManagerError):
    """(name, version) already registered — never silently replaced."""


class BadVersionError(PackageManagerError):
    """Version string is not semver MAJOR.MINOR.PATCH."""


class BadRangeError(PackageManagerError):
    """Version-range string has an unknown shape."""


class NoSatisfyingVersionError(PackageManagerError):
    """No registered version of a package satisfies a range."""


class VersionConflictError(PackageManagerError):
    """Two constraints on the same package cannot both be satisfied."""


class DependencyCycleError(PackageManagerError):
    """The dependency graph contains a cycle."""


class AlreadyInstalledError(PackageManagerError):
    """Root package already installed; uninstall it first."""


class RequiredByError(PackageManagerError):
    """Refused to uninstall a package another installed package needs."""


# ---------------------------------------------------------------------------
# canonical encoding / digest
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Type-tagged canonical encoding. Bool != int; floats refused."""
    if value is None:
        return "Z"
    if isinstance(value, bool):
        return "B1" if value else "B0"
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise PackageManagerError(f"integer magnitude >= 2**53 refused: {value!r}")
        return f"N{value}"
    if isinstance(value, float):
        raise PackageManagerError(f"floats refused: {value!r}")
    if isinstance(value, str):
        return "S" + json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "L[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: kv[0])
        for k in value:
            if not isinstance(k, str):
                raise PackageManagerError(f"non-str mapping key refused: {k!r}")
        return "M{" + ",".join(_canonical(k) + ":" + _canonical(v) for k, v in items) + "}"
    raise PackageManagerError(f"non-canonicalizable value refused: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    body = "|".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PackageManagerError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise PackageManagerError(f"package name invalid: {name!r}")
    return name


def _parse_version(version: Any) -> Tuple[int, int, int]:
    if not isinstance(version, str) or not _SEMVER_RE.match(version):
        raise BadVersionError(f"version must be semver MAJOR.MINOR.PATCH, got {version!r}")
    return tuple(int(p) for p in version.split("."))  # type: ignore[return-value]


def _parse_range(range_str: Any) -> Tuple[str, Tuple[int, int, int] | None]:
    """Parse a range into (kind, base_version). 'star' has no base."""
    if not isinstance(range_str, str):
        raise BadRangeError(f"range must be a str, got {range_str!r}")
    s = range_str.strip()
    if s == "*":
        return ("star", None)
    if s.startswith("^") or s.startswith("~"):
        kind = "caret" if s[0] == "^" else "tilde"
        return (kind, _parse_version(s[1:]))
    # bare version = exact
    return ("exact", _parse_version(s))


def _satisfies(version: Tuple[int, int, int], kind: str,
               base: Tuple[int, int, int] | None) -> bool:
    if kind == "star":
        return True
    assert base is not None
    if kind == "exact":
        return version == base
    if kind == "caret":
        # ^1.2.3 := >=1.2.3 <2.0.0 ; ^0.2.3 := >=0.2.3 <0.3.0 ; ^0.0.3 exact
        if base[0] != 0:
            return version[0] == base[0] and version >= base
        if base[1] != 0:
            return (version[0], version[1]) == (base[0], base[1]) and version >= base
        return version == base
    if kind == "tilde":
        # ~1.2.3 := >=1.2.3 <1.3.0
        return (version[0], version[1]) == (base[0], base[1]) and version >= base
    raise BadRangeError(f"unknown range kind: {kind!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PackageDependency:
    """One declared dependency: (name, range string)."""
    name: str
    range: str

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "range": self.range}


@dataclass(frozen=True)
class PackageRecord:
    """One registered (name, version) with its dependency ranges."""
    package_id: str
    name: str
    version: str
    version_tuple: Tuple[int, int, int]
    dependencies: Tuple[PackageDependency, ...]
    digest: str
    seq: int
    version_pin: str = VERSION
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "name": self.name,
            "version": self.version,
            "dependencies": [d.as_dict() for d in self.dependencies],
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": self.version_pin,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ResolvedPackage:
    """One (name, version) pinned by the resolver."""
    name: str
    version: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version, "digest": self.digest}


@dataclass(frozen=True)
class ResolutionReport:
    """Deterministic resolution: packages sorted by (name, version)."""
    root: str
    packages: Tuple[ResolvedPackage, ...]
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "packages": [p.as_dict() for p in self.packages],
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class InstallReceipt:
    """Frozen record of an install: topological install order."""
    install_id: str
    root: str
    packages: Tuple[ResolvedPackage, ...]
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "install_id": self.install_id,
            "root": self.root,
            "packages": [p.as_dict() for p in self.packages],
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class LockEntry:
    """One pinned (name, version) in a lock file."""
    name: str
    version: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version, "digest": self.digest}


@dataclass(frozen=True)
class LockFile:
    """Package-lock: exact versions + re-derivable pin."""
    lock_id: str
    entries: Tuple[LockEntry, ...]
    digest: str
    seq: int

    def verify(self) -> bool:
        """Re-derive the lock digest from its entries."""
        body = {
            "entries": [{"name": e.name, "version": e.version, "digest": e.digest}
                        for e in self.entries],
            "version": VERSION,
        }
        return _pin(body) == self.digest

    def as_dict(self) -> Dict[str, Any]:
        return {
            "lock_id": self.lock_id,
            "entries": [e.as_dict() for e in self.entries],
            "digest": self.digest,
            "seq": self.seq,
        }


# ---------------------------------------------------------------------------
# manager
# ---------------------------------------------------------------------------

class PackageManager:
    """npm-style install/resolve/lock ledger (simulated, deterministic)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._pkg_counter = 0
        self._install_counter = 0
        self._lock_counter = 0
        # name -> version_str -> PackageRecord
        self._registry: Dict[str, Dict[str, PackageRecord]] = {}
        # installed root name -> InstallReceipt
        self._installed: Dict[str, InstallReceipt] = {}
        # lock history
        self._locks: Dict[str, LockFile] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ---------------------------------------------------

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise PackageManagerError(f"seq must strictly increase, got {seq!r}")
        self._last_seq = seq
        return seq

    def _audit_emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(package_manager_audit_event(kind, seq, **detail))

    # -- registry ---------------------------------------------------------

    def register(self, name: Any, version: Any, seq: Any,
                 dependencies: Optional[List[Tuple[Any, Any]]] = None) -> PackageRecord:
        """Register one (name, version) with its declared dep ranges."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            name = _check_name(name)
            version_tuple = _parse_version(version)
            version = str(version)
            deps: List[PackageDependency] = []
            for item in dependencies or []:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise PackageManagerError(f"dependency must be (name, range), got {item!r}")
                dep_name = _check_name(item[0])
                kind, _base = _parse_range(item[1])  # validates the range shape
                if dep_name == name:
                    raise PackageManagerError(f"package cannot depend on itself: {name!r}")
                deps.append(PackageDependency(dep_name, str(item[1])))
            versions = self._registry.setdefault(name, {})
            if version in versions:
                raise DuplicatePackageError(f"already registered: {name}@{version}")
            self._pkg_counter += 1
            pkg_id = f"pkg-{self._pkg_counter}"
            digest = _pin({"name": name, "version": version,
                           "deps": [(d.name, d.range) for d in deps],
                           "version": VERSION})
            record = PackageRecord(pkg_id, name, version, version_tuple,
                                   tuple(deps), digest, seq)
            versions[version] = record
            self._audit_emit("registered", seq, package_id=pkg_id, name=name,
                             version=version)
            return record

    # -- resolution -------------------------------------------------------

    def _candidates(self, name: str) -> List[Tuple[int, int, int]]:
        if name not in self._registry:
            raise UnknownPackageError(f"unknown package: {name!r}")
        return sorted(v.version_tuple for v in self._registry[name].values())

    def _resolve_graph(self, root_name: str, root_range: str) -> List[ResolvedPackage]:
        """Depth-first resolution with constraint accumulation.

        Picks the highest version satisfying ALL recorded constraints for
        each name (npm's "max satisfying" discipline). Deterministic:
        visited order is sorted.
        """
        constraints: Dict[str, List[Tuple[str, Tuple[int, int, int] | None]]] = {}
        kind, base = _parse_range(root_range)
        constraints[root_name] = [(kind, base)]
        chosen: Dict[str, Tuple[int, int, int]] = {}
        visiting: List[str] = []

        def pick(name: str) -> Tuple[int, int, int]:
            cands = self._candidates(name)
            satisfying = [v for v in cands
                          if all(_satisfies(v, k, b) for k, b in constraints[name])]
            if not satisfying:
                if name not in chosen:
                    raise NoSatisfyingVersionError(
                        f"no version of {name!r} satisfies {constraints[name]!r}")
                raise VersionConflictError(
                    f"{name!r}: {constraints[name]!r} excludes already-chosen "
                    f"{_fmt(chosen[name])}")
            return satisfying[-1]

        def visit(name: str) -> None:
            if name in visiting:
                raise DependencyCycleError(
                    f"dependency cycle: {' -> '.join(visiting + [name])}")
            if name in chosen:
                # re-check: new constraints must still hold for the pick
                want = pick(name)
                if want != chosen[name]:
                    raise VersionConflictError(
                        f"{name!r}: constraint conflict, chose "
                        f"{_fmt(chosen[name])} but now need {_fmt(want)}")
                return
            visiting.append(name)
            version = pick(name)
            chosen[name] = version
            record = self._by_tuple(name, version)
            for dep in sorted(record.dependencies, key=lambda d: d.name):
                dk, db = _parse_range(dep.range)
                constraints.setdefault(dep.name, []).append((dk, db))
                visit(dep.name)
            visiting.pop()

        visit(root_name)
        resolved = []
        for name in sorted(chosen):
            version_str = _fmt(chosen[name])
            digest = _pin({"name": name, "version": version_str, "version": VERSION})
            resolved.append(ResolvedPackage(name, version_str, digest))
        return resolved

    def _by_tuple(self, name: str, version: Tuple[int, int, int]) -> PackageRecord:
        version_str = _fmt(version)
        try:
            return self._registry[name][version_str]
        except KeyError:
            raise UnknownPackageError(f"unknown: {name}@{version_str}")  # pragma: no cover

    def resolve(self, name: Any, version_range: Any, seq: Any) -> ResolutionReport:
        """Pure resolution view (no ledger mutation)."""
        with self._lock:
            seq = _check_seq(seq)
            name = _check_name(name)
            version_range = str(version_range)
            _parse_range(version_range)  # validate shape
            packages = tuple(self._resolve_graph(name, version_range))
            digest = _pin({"root": name,
                           "packages": [(p.name, p.version, p.digest) for p in packages],
                           "version": VERSION})
            self._audit_emit("resolved", seq, name=name, range=version_range)
            return ResolutionReport(name, packages, digest, seq)

    # -- install / uninstall ----------------------------------------------

    def install(self, name: Any, version_range: Any, seq: Any) -> InstallReceipt:
        """Resolve + pin a frozen install receipt (topological order)."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            name = _check_name(name)
            version_range = str(version_range)
            _parse_range(version_range)
            if name in self._installed:
                raise AlreadyInstalledError(f"already installed: {name!r}")
            resolved = self._resolve_graph(name, version_range)
            # topological order: dependencies before dependents
            graph = self._resolve_graph(name, version_range)
            order = self._topo_order(graph)
            self._install_counter += 1
            install_id = f"ins-{self._install_counter}"
            digest = _pin({"install_id": install_id, "root": name,
                           "packages": [(p.name, p.version, p.digest) for p in order],
                           "version": VERSION})
            receipt = InstallReceipt(install_id, name, tuple(order), digest, seq)
            self._installed[name] = receipt
            self._audit_emit("installed", seq, install_id=install_id, name=name)
            return receipt

    def _topo_order(self, resolved: List[ResolvedPackage]) -> List[ResolvedPackage]:
        by_name = {p.name: p for p in resolved}
        order: List[ResolvedPackage] = []
        seen: set = set()
        temp: set = set()

        def emit(name: str) -> None:
            if name in seen:
                return
            if name in temp:  # cycle already rejected in _resolve_graph
                return
            temp.add(name)
            record = self._registry[name][by_name[name].version]
            for dep in sorted(record.dependencies, key=lambda d: d.name):
                emit(dep.name)
            temp.discard(name)
            seen.add(name)
            order.append(by_name[name])

        for p in resolved:
            emit(p.name)
        return order

    def uninstall(self, name: Any, seq: Any) -> None:
        """Uninstall a root. Refused if another installed root depends on it."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            name = _check_name(name)
            if name not in self._installed:
                raise UnknownPackageError(f"not installed: {name!r}")
            needed_by = [root for root, receipt in self._installed.items()
                         if root != name
                         and any(p.name == name for p in receipt.packages)]
            if needed_by:
                raise RequiredByError(
                    f"{name!r} is required by installed: {sorted(needed_by)}")
            del self._installed[name]
            self._audit_emit("uninstalled", seq, name=name)

    # -- lock ---------------------------------------------------------------

    def lock(self, seq: Any) -> LockFile:
        """Pin exact installed versions (package-lock.json discipline)."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            dedup: Dict[str, LockEntry] = {}
            for receipt in self._installed.values():
                for p in receipt.packages:
                    if p.name in dedup:
                        if dedup[p.name].version != p.version:
                            raise VersionConflictError(
                                f"installed roots disagree on {p.name!r}: "
                                f"{dedup[p.name].version} vs {p.version}")
                        continue
                    dedup[p.name] = LockEntry(p.name, p.version, p.digest)
            ordered = tuple(dedup[name] for name in sorted(dedup))
            self._lock_counter += 1
            lock_id = f"lk-{self._lock_counter}"
            digest = _pin({"entries": [{"name": e.name, "version": e.version,
                                        "digest": e.digest} for e in ordered],
                           "version": VERSION})
            lockfile = LockFile(lock_id, ordered, digest, seq)
            self._locks[lock_id] = lockfile
            self._audit_emit("locked", seq, lock_id=lock_id)
            return lockfile

    # -- views ----------------------------------------------------------------

    def registry_names(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._registry))

    def versions(self, name: Any) -> Tuple[str, ...]:
        with self._lock:
            name = _check_name(name)
            if name not in self._registry:
                raise UnknownPackageError(f"unknown package: {name!r}")
            return tuple(sorted(self._registry[name],
                                key=lambda v: tuple(int(p) for p in v.split("."))))

    def installed_roots(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._installed))

    def install_receipt(self, name: Any) -> InstallReceipt:
        with self._lock:
            name = _check_name(name)
            if name not in self._installed:
                raise UnknownPackageError(f"not installed: {name!r}")
            return self._installed[name]

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def _fmt(version: Tuple[int, int, int]) -> str:
    return ".".join(str(p) for p in version)


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("registered", "resolved", "installed", "uninstalled",
                "locked", "rejected")


def package_manager_audit_event(kind: str, seq: int,
                                **detail: Any) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record. Ids + pins only; never payloads."""
    if kind not in _AUDIT_KINDS:
        raise PackageManagerError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": VERSION,
        "module_schema": SCHEMA,
    }
    event.update({k: _canonical(v) for k, v in detail.items()})
    return event


def main() -> None:
    """Self-check: register, resolve, install, lock, refusals."""
    pm = PackageManager()
    pm.register("leftpad", "1.0.0", 0)
    pm.register("leftpad", "1.1.0", 1)
    pm.register("app", "2.0.0", 2, dependencies=[("leftpad", "^1.0.0")])
    rep = pm.resolve("app", "^2.0.0", 3)
    assert [p.version for p in rep.packages if p.name == "leftpad"] == ["1.1.0"]
    receipt = pm.install("app", "^2.0.0", 4)
    assert receipt.packages[0].name == "leftpad"  # topological order
    lock = pm.lock(5)
    assert lock.verify()
    assert [e.name for e in lock.entries] == ["app", "leftpad"]
    # conflict refusal: combo needs leftpad ^1.0.0 (via app) AND 1.0.0 (via other)
    pm.register("other", "1.0.0", 6, dependencies=[("leftpad", "1.0.0")])
    pm.register("combo", "1.0.0", 7,
                dependencies=[("app", "^2.0.0"), ("other", "1.0.0")])
    try:
        pm.resolve("combo", "1.0.0", 8)
    except VersionConflictError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected VersionConflictError")
    print("package-manager OK: register, resolve, install, lock, refusals")


if __name__ == "__main__":
    main()
