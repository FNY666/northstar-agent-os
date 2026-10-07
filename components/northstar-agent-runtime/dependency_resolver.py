"""Package dependency resolver: constraint solving as deterministic bookkeeping.

Research note: package resolution (pip, npm, Cargo, PubGrub) reduces to a
constraint-satisfaction problem — pick one version per package such that
every declared requirement and every transitive dependency bound holds and
no declared conflict coexists. PubGrub (nex3/pubgrub, 2018) showed that
CDCL-style unit propagation gives *explainable* failures ("because X
requires Y >= 2 and Z requires Y < 2"); this module keeps the same shape
at a smaller scale: a backtracking solver with chronological backjumping
over a *host-reported* package index, plus a blame heuristic that names
which root requirements participate in a conflict.

* **Deterministic** — packages are expanded in sorted name order,
  candidate versions are tried newest-first, and the whole search replays
  to identical solutions and digest pins on repeated runs. No randomness,
  no wall-clock.
* **Newest-wins preference** — among satisfying assignments the solver
  returns the one found by the deterministic order, which prefers newer
  versions; the preference is a documented policy, not a global
  optimum (no "best" assignment is claimed).
* **Fail-closed** — unregistered packages, empty version sets, malformed
  specs, conflicting constraints, and rewinded seqs raise; unsatisfiable
  roots raise :class:`UnsatisfiableError` instead of returning a sentinel
  or a partial assignment.

Honest scope: ``solve()`` proves "this assignment satisfies the
*reported* index and requirements", never "these versions are safe,
compatible in the real world, or even exist". The index is host-reported;
a lying host gets a lying solution. ``conflicts()`` names requirements
whose individual removal restores solvability — a blame heuristic, not a
minimal unsatisfiable core.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
DEPENDENCY_RESOLVER_VERSION = "dependency-resolver.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.dependency-resolver.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Hash domain separator so resolver pins cannot collide with other digests.
_HASH_DOMAIN = b"northstar.dependency-resolver.v1\x00"

#: Hard cap on registered versions of one package (guardrail).
MAX_VERSIONS_PER_PACKAGE = 1024

#: Hard cap on packages in one resolver (guardrail).
MAX_PACKAGES = 10_000

#: Hard cap on deps declared by one version (guardrail).
MAX_DEPS_PER_VERSION = 256

#: Backtracking step budget (guardrail against pathological search).
DEFAULT_MAX_BACKTRACK_STEPS = 200_000

#: Comparator operators in the pinned constraint grammar.
_OPERATORS = ("==", "!=", ">=", "<=", ">", "<")

#: Fixed audit event kinds.
_AUDIT_KINDS = (
    "package-added",
    "required",
    "solved",
    "conflict-reported",
    "rejected",
)


class DependencyResolverError(Exception):
    """Base fail-closed dependency resolver error."""


class BadVersionError(DependencyResolverError):
    """Raised for version text that is not dotted-numeric."""


class BadSpecError(DependencyResolverError):
    """Raised for constraint specs outside the pinned grammar."""


class DuplicatePackageVersionError(DependencyResolverError):
    """Raised when registering an already-registered (package, version)."""


class UnknownPackageError(DependencyResolverError):
    """Raised when a package name is not registered at all."""


class BadDependencyError(DependencyResolverError):
    """Raised for malformed dependency declarations."""


class SeqOrderError(DependencyResolverError):
    """Raised when a caller seq is not strictly increasing."""


class UnsatisfiableError(DependencyResolverError):
    """Raised when no assignment satisfies the requirements."""


class SearchLimitError(DependencyResolverError):
    """Raised when the backtracking budget is exhausted (fail-closed)."""


def parse_version(text: Any) -> Tuple[int, ...]:
    """Parse dotted-numeric version text into a comparable tuple.

    Fail-closed: non-str, empty, non-numeric segments, and absurdly long
    versions are refused. Integral floats are NOT accepted — versions are
    text at the boundary (the batch-5 JCS caveat: ``"1.10"`` is not the
    float 1.1).
    """
    if not isinstance(text, str) or not text:
        raise BadVersionError(f"version must be a non-empty str, got {text!r}")
    if len(text) > 64:
        raise BadVersionError(f"version text too long: {text!r}")
    parts = text.split(".")
    if len(parts) > 8:
        raise BadVersionError(f"too many version segments: {text!r}")
    nums: List[int] = []
    for part in parts:
        if not part.isdigit():
            raise BadVersionError(f"non-numeric version segment in {text!r}")
        nums.append(int(part))
    return tuple(nums)


def _version_cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """Compare version tuples with zero padding; -1/0/1."""
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def parse_spec(spec: Any) -> Tuple[Tuple[str, Tuple[int, ...]], ...]:
    """Parse a constraint spec like ``">=1.2,<3"`` into pinned form.

    Grammar: one or more ``<op><version>`` clauses joined by commas, op
    in ``== != >= <= > <``. Whitespace around clauses is tolerated.
    """
    if not isinstance(spec, str) or not spec.strip():
        raise BadSpecError(f"spec must be a non-empty str, got {spec!r}")
    if len(spec) > 256:
        raise BadSpecError("spec text too long")
    clauses: List[Tuple[str, Tuple[int, ...]]] = []
    for raw in spec.split(","):
        part = raw.strip()
        for op in _OPERATORS:
            if part.startswith(op):
                version = parse_version(part[len(op):].strip())
                clauses.append((op, version))
                break
        else:
            raise BadSpecError(f"unknown comparator in spec clause {part!r}")
    return tuple(clauses)


def spec_matches(version: Tuple[int, ...], spec: Tuple[Tuple[str, Tuple[int, ...]], ...]) -> bool:
    """Check a parsed version tuple against every clause of a spec."""
    for op, bound in spec:
        c = _version_cmp(version, bound)
        if op == "==":
            if c != 0:
                return False
        elif op == "!=":
            if c == 0:
                return False
        elif op == ">=":
            if c < 0:
                return False
        elif op == "<=":
            if c > 0:
                return False
        elif op == ">":
            if c <= 0:
                return False
        elif op == "<":
            if c >= 0:
                return False
    return True


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {seq!r}")
    if seq < 0:
        raise SeqOrderError(f"seq must be non-negative, got {seq}")
    return seq


def _check_package_name(name: Any) -> str:
    if not isinstance(name, str) or not name:
        raise BadDependencyError(f"package name must be a non-empty str, got {name!r}")
    if len(name) > 128:
        raise BadDependencyError(f"package name too long: {name!r}")
    return name


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(_HASH_DOMAIN + jcs_canonical_json(obj)).hexdigest()


@dataclass(frozen=True)
class PackageRecord:
    """One registered (package, version) with its declared edges."""

    package: str
    version: str
    version_tuple: Tuple[int, ...]
    deps: Tuple[Tuple[str, Tuple[Tuple[str, Tuple[int, ...]], ...]], ...]
    conflicts: Tuple[str, ...]
    seq: int
    digest: str
    version_str: str = DEPENDENCY_RESOLVER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "version_tuple": list(self.version_tuple),
            "deps": [(p, [(op, list(v)) for op, v in s]) for p, s in self.deps],
            "conflicts": list(self.conflicts),
            "seq": self.seq,
            "digest": self.digest,
            "version_str": self.version_str,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RequirementRecord:
    """One root requirement: ``package`` must match ``spec``."""

    req_id: str
    package: str
    spec: str
    parsed_spec: Tuple[Tuple[str, Tuple[int, ...]], ...]
    seq: int
    digest: str
    version_str: str = DEPENDENCY_RESOLVER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "req_id": self.req_id,
            "package": self.package,
            "spec": self.spec,
            "parsed_spec": [(op, list(v)) for op, v in self.parsed_spec],
            "seq": self.seq,
            "digest": self.digest,
            "version_str": self.version_str,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SolutionRecord:
    """A satisfying assignment: package -> chosen version text."""

    solution_id: str
    assignments: Tuple[Tuple[str, str], ...]
    seq: int
    digest: str
    version_str: str = DEPENDENCY_RESOLVER_VERSION
    schema: str = SCHEMA_PIN

    def version_of(self, package: str) -> str:
        for name, version in self.assignments:
            if name == package:
                return version
        raise UnknownPackageError(f"package {package!r} not in solution")

    def verify(self) -> bool:
        body = {
            "solution_id": self.solution_id,
            "assignments": [list(pair) for pair in self.assignments],
            "version": self.version_str,
        }
        return _digest(body) == self.digest

    def as_dict(self) -> Dict[str, Any]:
        return {
            "solution_id": self.solution_id,
            "assignments": [list(pair) for pair in self.assignments],
            "seq": self.seq,
            "digest": self.digest,
            "version_str": self.version_str,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ConflictReport:
    """Blame analysis for an unsatisfiable requirement set."""

    conflict_id: str
    conflicting: bool
    blamed_req_ids: Tuple[str, ...]
    unresolvable: bool
    seq: int
    digest: str
    version_str: str = DEPENDENCY_RESOLVER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "conflicting": self.conflicting,
            "blamed_req_ids": list(self.blamed_req_ids),
            "unresolvable": self.unresolvable,
            "seq": self.seq,
            "digest": self.digest,
            "version_str": self.version_str,
            "schema": self.schema,
        }


class DependencyResolver:
    """Deterministic constraint solver over a host-reported package index.

    ``add()`` registers versions with their dependency edges;
    ``require()`` pins root constraints; ``solve()`` returns the
    newest-first deterministic satisfying assignment; ``conflicts()``
    reports which root requirements participate in a conflict.
    """

    def __init__(self, max_backtrack_steps: int = DEFAULT_MAX_BACKTRACK_STEPS) -> None:
        if isinstance(max_backtrack_steps, bool) or not isinstance(max_backtrack_steps, int):
            raise DependencyResolverError("max_backtrack_steps must be an int")
        if max_backtrack_steps < 1:
            raise DependencyResolverError("max_backtrack_steps must be >= 1")
        self._max_backtrack_steps = max_backtrack_steps
        self._lock = threading.RLock()
        self._versions: Dict[str, List[Tuple[Tuple[int, ...], PackageRecord]]] = {}
        self._requirements: Dict[str, RequirementRecord] = {}
        self._req_counter = 0
        self._sol_counter = 0
        self._conflict_counter = 0
        self._last_seq = -1
        self._audit_log: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase (last={self._last_seq}, got={seq})")
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(dependency_resolver_audit_event(kind, seq, **detail))

    # -- mutation ----------------------------------------------------------

    def add(
        self,
        package: Any,
        version: Any,
        seq: Any,
        deps: Any = (),
        conflicts: Any = (),
    ) -> PackageRecord:
        """Register one (package, version) with dependency edges.

        ``deps`` is a tuple of ``(dep_package, spec)`` pairs; ``conflicts``
        is a tuple of package names this version cannot coexist with.
        A failed mutation still consumes its seq (fail-closed ledger
        position).
        """
        with self._lock:
            seq = self._claim_seq(seq)
            name = _check_package_name(package)
            vtuple = parse_version(version)
            if len(self._versions) >= MAX_PACKAGES and name not in self._versions:
                raise DependencyResolverError(f"too many packages (cap {MAX_PACKAGES})")
            parsed_deps = self._parse_deps(deps)
            parsed_conflicts = self._parse_conflicts(conflicts)
            for existing_vt, _ in self._versions.get(name, ()):  # noqa: B007
                if _version_cmp(existing_vt, vtuple) == 0:
                    raise DuplicatePackageVersionError(
                        f"package {name!r} version {version!r} already registered"
                    )
            bucket = self._versions.setdefault(name, [])
            if len(bucket) >= MAX_VERSIONS_PER_PACKAGE:
                raise DependencyResolverError(
                    f"too many versions for {name!r} (cap {MAX_VERSIONS_PER_PACKAGE})"
                )
            digest = _digest(
                {
                    "package": name,
                    "version": version,
                    "deps": [[p, [[op, list(v)] for op, v in s]] for p, s in parsed_deps],
                    "conflicts": list(parsed_conflicts),
                    "version": DEPENDENCY_RESOLVER_VERSION,
                }
            )
            record = PackageRecord(
                package=name,
                version=version,
                version_tuple=vtuple,
                deps=parsed_deps,
                conflicts=parsed_conflicts,
                seq=seq,
                digest=digest,
            )
            bucket.append((vtuple, record))
            bucket.sort(key=lambda item: item[0], reverse=True)  # newest-first
            self._audit("package-added", seq, package=name, version=version)
            return record

    @staticmethod
    def _parse_deps(deps: Any) -> Tuple[Tuple[str, Tuple[Tuple[str, Tuple[int, ...]], ...]], ...]:
        if not isinstance(deps, tuple):
            raise BadDependencyError(f"deps must be a tuple, got {type(deps).__name__}")
        if len(deps) > MAX_DEPS_PER_VERSION:
            raise BadDependencyError(f"too many deps (cap {MAX_DEPS_PER_VERSION})")
        out: List[Tuple[str, Tuple[Tuple[str, Tuple[int, ...]], ...]]] = []
        seen: set = set()
        for item in deps:
            if not isinstance(item, tuple) or len(item) != 2:
                raise BadDependencyError(f"dep must be a (package, spec) pair, got {item!r}")
            dep_name, spec = item
            dep_name = _check_package_name(dep_name)
            parsed = parse_spec(spec)
            if (dep_name, parsed) in seen:
                raise BadDependencyError(f"duplicate dep {dep_name!r}")
            seen.add((dep_name, parsed))
            out.append((dep_name, parsed))
        return tuple(out)

    @staticmethod
    def _parse_conflicts(conflicts: Any) -> Tuple[str, ...]:
        if not isinstance(conflicts, tuple):
            raise BadDependencyError(f"conflicts must be a tuple, got {type(conflicts).__name__}")
        out: List[str] = []
        seen: set = set()
        for name in conflicts:
            name = _check_package_name(name)
            if name in seen:
                raise BadDependencyError(f"duplicate conflict {name!r}")
            seen.add(name)
            out.append(name)
        return tuple(out)

    def require(self, package: Any, spec: Any, seq: Any) -> RequirementRecord:
        """Pin a root requirement: ``package`` must match ``spec``."""
        with self._lock:
            seq = self._claim_seq(seq)
            name = _check_package_name(package)
            parsed = parse_spec(spec)
            self._req_counter += 1
            req_id = f"req-{self._req_counter}"
            digest = _digest(
                {
                    "req_id": req_id,
                    "package": name,
                    "spec": spec,
                    "version": DEPENDENCY_RESOLVER_VERSION,
                }
            )
            record = RequirementRecord(
                req_id=req_id,
                package=name,
                spec=spec,
                parsed_spec=parsed,
                seq=seq,
                digest=digest,
            )
            self._requirements[req_id] = record
            self._audit("required", seq, req_id=req_id, package=name, spec=spec)
            return record

    # -- solving -----------------------------------------------------------

    def solve(self, seq: Any) -> SolutionRecord:
        """Return a satisfying assignment (newest-first deterministic).

        Pure view of the index + requirements: the seq is validated as a
        non-negative int for pinning but does not consume the mutation
        ledger position.
        """
        with self._lock:
            seq = _check_seq(seq)
            assignment = self._search()
            self._sol_counter += 1
            solution_id = f"sol-{self._sol_counter}"
            pairs = tuple(sorted((name, rec.version) for name, rec in assignment.items()))
            digest = _digest(
                {
                    "solution_id": solution_id,
                    "assignments": [list(pair) for pair in pairs],
                    "version": DEPENDENCY_RESOLVER_VERSION,
                }
            )
            record = SolutionRecord(
                solution_id=solution_id,
                assignments=pairs,
                seq=seq,
                digest=digest,
            )
            self._audit("solved", seq, solution_id=solution_id, packages=len(pairs))
            return record

    def conflicts(self, seq: Any) -> ConflictReport:
        """Blame analysis for the current requirement set.

        If solvable, ``conflicting`` is False. Otherwise each root
        requirement is dropped in turn and re-solved; requirements whose
        individual removal restores solvability are blamed. If none do,
        ``unresolvable`` is True (the conflict lives in transitive edges
        beyond single-requirement blame).
        """
        with self._lock:
            seq = _check_seq(seq)
            try:
                self._search()
            except UnsatisfiableError:
                pass
            else:
                return self._report(seq, conflicting=False, blamed=(), unresolvable=False)
            blamed: List[str] = []
            for req_id in sorted(self._requirements):
                try:
                    self._search(exclude_req_id=req_id)
                except UnsatisfiableError:
                    continue
                blamed.append(req_id)
            return self._report(
                seq,
                conflicting=True,
                blamed=tuple(blamed),
                unresolvable=len(blamed) == 0,
            )

    def _report(
        self, seq: int, conflicting: bool, blamed: Tuple[str, ...], unresolvable: bool
    ) -> ConflictReport:
        self._conflict_counter += 1
        conflict_id = f"cf-{self._conflict_counter}"
        digest = _digest(
            {
                "conflict_id": conflict_id,
                "conflicting": conflicting,
                "blamed": list(blamed),
                "unresolvable": unresolvable,
                "version": DEPENDENCY_RESOLVER_VERSION,
            }
        )
        record = ConflictReport(
            conflict_id=conflict_id,
            conflicting=conflicting,
            blamed_req_ids=blamed,
            unresolvable=unresolvable,
            seq=seq,
            digest=digest,
        )
        self._audit("conflict-reported", seq, conflict_id=conflict_id, conflicting=conflicting)
        return record

    def _search(
        self, exclude_req_id: Optional[str] = None
    ) -> Dict[str, PackageRecord]:
        """Backtracking search; raises UnsatisfiableError on failure."""
        needed: Dict[str, List[Tuple[str, Tuple[Tuple[str, Tuple[int, ...]], ...]]]] = {}
        for req in self._requirements.values():
            if req.req_id == exclude_req_id:
                continue
            needed.setdefault(req.package, []).append((req.req_id, req.parsed_spec))

        assignment: Dict[str, PackageRecord] = {}
        steps = 0
        max_steps = self._max_backtrack_steps

        def candidates(pkg: str) -> List[PackageRecord]:
            specs = [spec for _, spec in needed.get(pkg, [])]
            out: List[PackageRecord] = []
            for vtuple, rec in self._versions.get(pkg, ()):
                if all(spec_matches(vtuple, spec) for spec in specs):
                    out.append(rec)
            return out  # newest-first: bucket order

        def dfs() -> bool:
            nonlocal steps
            steps += 1
            if steps > max_steps:
                raise SearchLimitError(
                    f"backtracking budget exhausted ({max_steps} steps)"
                )
            remaining = sorted(p for p in needed if p not in assignment)
            if not remaining:
                return True
            pkg = remaining[0]
            for rec in candidates(pkg):
                if any(q in rec.conflicts for q in assignment):
                    continue
                if any(pkg in other.conflicts for other in assignment.values()):
                    continue
                assignment[pkg] = rec
                added: List[str] = []
                alive = True
                for dep_pkg, dep_spec in rec.deps:
                    if dep_pkg in assignment:
                        if not spec_matches(assignment[dep_pkg].version_tuple, dep_spec):
                            alive = False
                            break
                        continue
                    if not self._versions.get(dep_pkg):
                        alive = False
                        break
                    needed.setdefault(dep_pkg, []).append(
                        (f"dep:{pkg}@{rec.version}", dep_spec)
                    )
                    added.append(dep_pkg)
                if alive and dfs():
                    return True
                del assignment[pkg]
                for dep_pkg in added:
                    needed[dep_pkg].pop()
                    if not needed[dep_pkg]:
                        del needed[dep_pkg]
            return False

        if dfs():
            return assignment
        raise UnsatisfiableError("no assignment satisfies the requirements")

    # -- views --------------------------------------------------------------

    def package_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._versions))

    def versions_of(self, package: str) -> Tuple[str, ...]:
        with self._lock:
            name = _check_package_name(package)
            if name not in self._versions:
                raise UnknownPackageError(f"package {name!r} not registered")
            return tuple(rec.version for _, rec in self._versions[name])

    def requirements(self) -> Tuple[RequirementRecord, ...]:
        with self._lock:
            return tuple(self._requirements[k] for k in sorted(self._requirements))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def dependency_resolver_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for resolver activity."""
    if kind not in _AUDIT_KINDS:
        raise DependencyResolverError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "event": kind,
        "audit_seq": seq,
        "module_version": DEPENDENCY_RESOLVER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    event.update(detail)
    return event


def main() -> None:
    """Self-check: register, require, solve, blame."""
    res = DependencyResolver()
    res.add("web", "1.0", 0, deps=(("db", ">=1.0,<2.0"),))
    res.add("web", "2.0", 1, deps=(("db", ">=2.0"),))
    res.add("db", "1.5", 2)
    res.add("db", "2.1", 3)
    res.require("web", ">=1.0", 4)
    sol = res.solve(5)
    assert sol.version_of("web") == "2.0", sol.as_dict()
    assert sol.version_of("db") == "2.1", sol.as_dict()
    assert sol.verify()

    bad = DependencyResolver()
    bad.add("a", "1.0", 0, deps=(("b", ">=2.0"),))
    bad.add("b", "1.0", 1)
    bad.require("a", "==1.0", 2)
    try:
        bad.solve(3)
    except UnsatisfiableError:
        pass
    else:
        raise AssertionError("expected UnsatisfiableError")
    rep = bad.conflicts(4)
    assert rep.conflicting and not rep.unresolvable, rep.as_dict()
    assert rep.blamed_req_ids == ("req-1",), rep.as_dict()

    print("dependency-resolver OK: add, require, solve newest-first, unsat, blame")


if __name__ == "__main__":
    main()
