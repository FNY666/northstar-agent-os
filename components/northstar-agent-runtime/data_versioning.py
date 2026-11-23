"""Data versioning — DVC/LakeFS-shaped dataset snapshot bookkeeping.

Research note (data versioning literature): DVC (Data Version Control)
and LakeFS model dataset versioning as a git-shaped DAG — immutable
commits pin *content digests* (never the bytes), branches are movable
pointers to commits, merges combine histories (fast-forward when one
side is an ancestor, three-way merge at the merge base otherwise),
and tags are immutable release pointers. This module takes the
intersection for a single-host deterministic ledger:

* **Commits book digests, not data**: ``commit`` records a
  host-reported dataset digest plus a message on a branch; the
  module never sees dataset bytes. Each commit is hash-chained to
  its parent(s), giving tamper-evident history.
* **Branches are pointers**: ``init_repo`` creates the default
  ``main`` branch; ``branch`` creates a named pointer at a commit;
  ``commit`` advances the branch head. Ids are never recycled.
* **Merges are declared decisions**: ``merge`` fast-forwards the
  target pointer when the target head is an ancestor of the source
  head (no new commit); otherwise it books a merge commit with two
  parents at the merge base (nearest common ancestor from the
  target side). The host reports conflicts via ``conflicts`` — any
  non-empty list refuses the merge fail-closed — and declares the
  merged dataset digest via ``result_digest``. The module performs
  no byte-level merge.
* **Tags pin releases**: ``tag`` books an immutable name → commit
  pointer.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool /
negative / rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), sha256 digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* dataset versions
deterministically. It stores no dataset bytes, cannot verify that a
digest matches any real data, cannot detect unreported changes, and
performs no actual three-way content merge — a merge commit records
the host's declaration that two histories were combined. Pair with a
real content store (a DVC remote, LakeFS, or S3) for production.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
DATA_VERSIONING_VERSION = "data-versioning.v1"

#: Schema pin carried by records and audit events.
DATA_VERSIONING_SCHEMA = "northstar.data-versioning.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Default branch created by ``init_repo``.
DEFAULT_BRANCH = "main"

#: Pinned merge strategies (booked as data; the module merges no bytes).
STRATEGY_RECURSIVE = "recursive"
STRATEGY_OURS = "ours"
STRATEGY_THEIRS = "theirs"
MERGE_STRATEGIES = (STRATEGY_RECURSIVE, STRATEGY_OURS, STRATEGY_THEIRS)

#: Commit-id prefix (module-minted, monotonic, never recycled).
COMMIT_PREFIX = "cmt-"

#: Merge-record-id prefix (module-minted, monotonic, never recycled).
MERGE_PREFIX = "mrg-"

#: Audit event kinds.
KIND_REPO_INITIALIZED = "data-versioning.repo-initialized"
KIND_COMMITTED = "data-versioning.committed"
KIND_BRANCH_CREATED = "data-versioning.branch-created"
KIND_MERGED = "data-versioning.merged"
KIND_TAGGED = "data-versioning.tagged"
KIND_REJECTED = "data-versioning.rejected"
_KINDS = (
    KIND_REPO_INITIALIZED,
    KIND_COMMITTED,
    KIND_BRANCH_CREATED,
    KIND_MERGED,
    KIND_TAGGED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"

#: Name / message length caps (fail-closed on overflow).
_MAX_NAME_LEN = 128
_MAX_MESSAGE_LEN = 1024
_MAX_HISTORY_LIMIT = 1000


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class DataVersioningError(ValueError):
    """Base error for data versioning."""


class BadRepoError(DataVersioningError):
    """Malformed repository id."""


class DuplicateRepoError(DataVersioningError):
    """A repository with this id is already initialized."""


class UnknownRepoError(DataVersioningError):
    """No repository with this id is initialized."""


class BadCommitError(DataVersioningError):
    """Malformed commit arguments (bad digest, message)."""


class UnknownCommitError(DataVersioningError):
    """No commit with this id exists."""


class BadBranchError(DataVersioningError):
    """Malformed branch name or branch source."""


class DuplicateBranchError(DataVersioningError):
    """A branch with this name already exists in the repository."""


class UnknownBranchError(DataVersioningError):
    """No branch with this name exists in the repository."""


class BadMergeError(DataVersioningError):
    """Malformed merge (bad strategy, self-merge, no common ancestor)."""


class AlreadyUpToDateError(DataVersioningError):
    """Source and target heads are identical; nothing to merge."""


class MergeConflictError(DataVersioningError):
    """Host-reported conflicts refuse the merge (fail-closed)."""


class BadTagError(DataVersioningError):
    """Malformed tag name."""


class DuplicateTagError(DataVersioningError):
    """A tag with this name already exists in the repository."""


class UnknownTagError(DataVersioningError):
    """No tag with this name exists in the repository."""


class SeqOrderError(DataVersioningError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DataVersioningError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DataVersioningError(f"{field_name} must be a non-empty string")
    return value


def _check_name(value: Any, field_name: str) -> str:
    name = _check_nonempty_str(value, field_name)
    if len(name) > _MAX_NAME_LEN:
        raise DataVersioningError(f"{field_name} exceeds {_MAX_NAME_LEN} chars")
    if any(ch.isspace() for ch in name):
        raise DataVersioningError(f"{field_name} must not contain whitespace")
    return name


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise DataVersioningError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DataVersioningError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DataVersioningError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoRecord:
    """A pinned dataset repository with its default branch."""

    repo_id: str
    default_branch: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["repo", self.repo_id, self.default_branch, self.seq], seed),
        )


@dataclass(frozen=True)
class CommitRecord:
    """An immutable dataset snapshot pin (hash-chained to its parents)."""

    commit_id: str
    repo_id: str
    branch: str
    message: str
    dataset_digest: str
    parents: tuple
    seq: int
    order: int
    prev_digest: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "commit",
                    self.commit_id,
                    self.repo_id,
                    self.branch,
                    self.message,
                    self.dataset_digest,
                    list(self.parents),
                    self.seq,
                    self.order,
                    self.prev_digest,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class BranchRecord:
    """A named movable pointer to a commit (``None`` head = no commits yet)."""

    repo_id: str
    name: str
    head_commit_id: Optional[str]
    created_seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["branch", self.repo_id, self.name, self.head_commit_id, self.created_seq],
                seed,
            ),
        )


@dataclass(frozen=True)
class MergeRecord:
    """A booked merge decision (fast-forward pointer move or merge commit)."""

    merge_id: str
    repo_id: str
    source_branch: str
    target_branch: str
    strategy: str
    fast_forward: bool
    base_commit_id: Optional[str]
    result_commit_id: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "merge",
                    self.merge_id,
                    self.repo_id,
                    self.source_branch,
                    self.target_branch,
                    self.strategy,
                    self.fast_forward,
                    self.base_commit_id,
                    self.result_commit_id,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class TagRecord:
    """An immutable name → commit pointer."""

    repo_id: str
    tag: str
    commit_id: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["tag", self.repo_id, self.tag, self.commit_id, self.seq], seed),
        )


def data_versioning_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for data versioning."""
    if kind not in _KINDS:
        raise DataVersioningError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "data_versioning",
        "module_version": DATA_VERSIONING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# DataVersioning
# ---------------------------------------------------------------------------


class DataVersioning:
    """Deterministic dataset-version bookkeeping (DVC/LakeFS-shaped).

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads validate the seq shape but do not consume it and write no
    audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._repos: dict[str, RepoRecord] = {}
        self._commits: dict[str, CommitRecord] = {}
        self._branches: dict[tuple, BranchRecord] = {}
        self._tags: dict[tuple, TagRecord] = {}
        self._merges: dict[str, MergeRecord] = {}
        self._commit_counter = 0
        self._merge_counter = 0
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(data_versioning_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _ancestors(self, commit_id: str) -> set:
        seen: set = set()
        stack = [commit_id]
        while stack:
            cid = stack.pop()
            if cid in seen:
                continue
            seen.add(cid)
            stack.extend(self._commits[cid].parents)
        return seen

    def _is_ancestor(self, maybe_ancestor: str, commit_id: str) -> bool:
        return maybe_ancestor in self._ancestors(commit_id)

    def _merge_base(self, target_head: str, source_head: str) -> Optional[str]:
        """Nearest common ancestor from the target side (BFS, deterministic)."""
        source_ancestors = self._ancestors(source_head)
        seen: set = set()
        queue = [target_head]
        while queue:
            cid = queue.pop(0)
            if cid in seen:
                continue
            seen.add(cid)
            if cid in source_ancestors:
                return cid
            queue.extend(self._commits[cid].parents)
        return None

    def _mint_commit(
        self,
        repo_id: str,
        branch: str,
        message: str,
        dataset_digest: str,
        parents: tuple,
        seq: int,
    ) -> CommitRecord:
        self._commit_counter += 1
        commit_id = f"{COMMIT_PREFIX}{self._commit_counter}"
        prev_digest = (
            self._commits[parents[0]].digest if parents else _GENESIS
        )
        digest = _pin(
            [
                "commit",
                commit_id,
                repo_id,
                branch,
                message,
                dataset_digest,
                list(parents),
                seq,
                self._commit_counter,
                prev_digest,
            ],
            self._seed,
        )
        record = CommitRecord(
            commit_id=commit_id,
            repo_id=repo_id,
            branch=branch,
            message=message,
            dataset_digest=dataset_digest,
            parents=tuple(parents),
            seq=seq,
            order=self._commit_counter,
            prev_digest=prev_digest,
            digest=digest,
        )
        self._commits[commit_id] = record
        key = (repo_id, branch)
        old = self._branches[key]
        self._branches[key] = BranchRecord(
            repo_id=repo_id,
            name=branch,
            head_commit_id=commit_id,
            created_seq=old.created_seq,
            digest=_pin(
                ["branch", repo_id, branch, commit_id, old.created_seq],
                self._seed,
            ),
        )
        return record

    def _require_repo(self, repo_id: str) -> RepoRecord:
        try:
            return self._repos[repo_id]
        except KeyError:
            raise UnknownRepoError(f"unknown repo: {repo_id!r}")

    def _require_branch(self, repo_id: str, branch: str) -> BranchRecord:
        try:
            return self._branches[(repo_id, branch)]
        except KeyError:
            raise UnknownBranchError(
                f"unknown branch {branch!r} in repo {repo_id!r}"
            )

    # -- mutations -----------------------------------------------------

    def init_repo(self, repo_id: str, seq: int) -> RepoRecord:
        """Initialize a repository with a default ``main`` branch."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                repo_id = _check_name(repo_id, "repo_id")
                if repo_id in self._repos:
                    raise DuplicateRepoError(f"repo already exists: {repo_id!r}")
            except DataVersioningError as exc:
                self._reject(seq, str(exc))
                raise
            record = RepoRecord(
                repo_id=repo_id,
                default_branch=DEFAULT_BRANCH,
                seq=seq,
                digest=_pin(["repo", repo_id, DEFAULT_BRANCH, seq], self._seed),
            )
            self._repos[repo_id] = record
            self._branches[(repo_id, DEFAULT_BRANCH)] = BranchRecord(
                repo_id=repo_id,
                name=DEFAULT_BRANCH,
                head_commit_id=None,
                created_seq=seq,
                digest=_pin(
                    ["branch", repo_id, DEFAULT_BRANCH, None, seq], self._seed
                ),
            )
            self._emit(KIND_REPO_INITIALIZED, seq, repo_id=repo_id)
            return record

    def commit(
        self,
        repo_id: str,
        branch: str,
        dataset_digest: str,
        message: str,
        seq: int,
    ) -> CommitRecord:
        """Book an immutable snapshot pin on a branch (advances the head)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                repo_id = _check_name(repo_id, "repo_id")
                branch = _check_name(branch, "branch")
                dataset_digest = _check_nonempty_str(dataset_digest, "dataset_digest")
                message = _check_nonempty_str(message, "message")
                if len(message) > _MAX_MESSAGE_LEN:
                    raise BadCommitError(
                        f"message exceeds {_MAX_MESSAGE_LEN} chars"
                    )
                self._require_repo(repo_id)
                branch_rec = self._require_branch(repo_id, branch)
                head = branch_rec.head_commit_id
                parents = () if head is None else (head,)
            except DataVersioningError as exc:
                self._reject(seq, str(exc))
                raise
            record = self._mint_commit(
                repo_id, branch, message, dataset_digest, parents, seq
            )
            self._emit(
                KIND_COMMITTED,
                seq,
                repo_id=repo_id,
                branch=branch,
                commit_id=record.commit_id,
                dataset_digest=dataset_digest,
                parents=list(parents),
            )
            return record

    def branch(
        self,
        repo_id: str,
        branch_name: str,
        from_commit_id: Optional[str],
        seq: int,
    ) -> BranchRecord:
        """Create a named branch pointer at a commit.

        ``from_commit_id=None`` points the new branch at the head of the
        repo's default branch.
        """
        seq = self._next_seq(seq)
        with self._lock:
            try:
                repo_id = _check_name(repo_id, "repo_id")
                branch_name = _check_name(branch_name, "branch_name")
                self._require_repo(repo_id)
                if (repo_id, branch_name) in self._branches:
                    raise DuplicateBranchError(
                        f"branch already exists: {branch_name!r}"
                    )
                if from_commit_id is None:
                    default_head = self._require_branch(
                        repo_id, DEFAULT_BRANCH
                    ).head_commit_id
                    if default_head is None:
                        raise BadBranchError(
                            "cannot branch from an empty repository"
                        )
                    from_commit_id = default_head
                else:
                    from_commit_id = _check_nonempty_str(
                        from_commit_id, "from_commit_id"
                    )
                try:
                    source = self._commits[from_commit_id]
                except KeyError:
                    raise UnknownCommitError(
                        f"unknown commit: {from_commit_id!r}"
                    )
                if source.repo_id != repo_id:
                    raise BadBranchError("commit belongs to another repo")
            except DataVersioningError as exc:
                self._reject(seq, str(exc))
                raise
            record = BranchRecord(
                repo_id=repo_id,
                name=branch_name,
                head_commit_id=from_commit_id,
                created_seq=seq,
                digest=_pin(
                    ["branch", repo_id, branch_name, from_commit_id, seq],
                    self._seed,
                ),
            )
            self._branches[(repo_id, branch_name)] = record
            self._emit(
                KIND_BRANCH_CREATED,
                seq,
                repo_id=repo_id,
                branch=branch_name,
                from_commit_id=from_commit_id,
            )
            return record

    def merge(
        self,
        repo_id: str,
        source_branch: str,
        target_branch: str,
        seq: int,
        strategy: str = STRATEGY_RECURSIVE,
        conflicts: Any = (),
        result_digest: Optional[str] = None,
    ) -> MergeRecord:
        """Merge ``source_branch`` into ``target_branch``.

        Fast-forwards the target pointer when the target head is an
        ancestor of the source head (no new commit). Otherwise books a
        merge commit with two parents at the merge base; the host must
        declare the merged dataset via ``result_digest`` and report
        any conflicting paths via ``conflicts`` (non-empty refuses).
        """
        seq = self._next_seq(seq)
        with self._lock:
            try:
                repo_id = _check_name(repo_id, "repo_id")
                source_branch = _check_name(source_branch, "source_branch")
                target_branch = _check_name(target_branch, "target_branch")
                if strategy not in MERGE_STRATEGIES:
                    raise BadMergeError(f"unknown strategy: {strategy!r}")
                if source_branch == target_branch:
                    raise BadMergeError("cannot merge a branch into itself")
                if not isinstance(conflicts, (list, tuple)):
                    raise BadMergeError("conflicts must be a list/tuple")
                for path in conflicts:
                    if not isinstance(path, str) or not path.strip():
                        raise BadMergeError("conflict paths must be non-empty strings")
                self._require_repo(repo_id)
                src = self._require_branch(repo_id, source_branch)
                tgt = self._require_branch(repo_id, target_branch)
                src_head = src.head_commit_id
                tgt_head = tgt.head_commit_id
                if src_head is None or tgt_head is None:
                    raise BadMergeError("cannot merge empty branches")
                if src_head == tgt_head:
                    raise AlreadyUpToDateError("branches already point at one commit")
                if conflicts:
                    raise MergeConflictError(
                        f"{len(conflicts)} host-reported conflict(s) refuse the merge"
                    )
            except DataVersioningError as exc:
                self._reject(seq, str(exc))
                raise

            self._merge_counter += 1
            merge_id = f"{MERGE_PREFIX}{self._merge_counter}"
            if self._is_ancestor(tgt_head, src_head):
                # Fast-forward: move the target pointer, no new commit.
                old = self._branches[(repo_id, target_branch)]
                self._branches[(repo_id, target_branch)] = BranchRecord(
                    repo_id=repo_id,
                    name=target_branch,
                    head_commit_id=src_head,
                    created_seq=old.created_seq,
                    digest=_pin(
                        ["branch", repo_id, target_branch, src_head, old.created_seq],
                        self._seed,
                    ),
                )
                record = MergeRecord(
                    merge_id=merge_id,
                    repo_id=repo_id,
                    source_branch=source_branch,
                    target_branch=target_branch,
                    strategy=strategy,
                    fast_forward=True,
                    base_commit_id=tgt_head,
                    result_commit_id=src_head,
                    seq=seq,
                    digest=_pin(
                        [
                            "merge", merge_id, repo_id, source_branch,
                            target_branch, strategy, True, tgt_head,
                            src_head, seq,
                        ],
                        self._seed,
                    ),
                )
            else:
                base = self._merge_base(tgt_head, src_head)
                if base is None:
                    self._reject(seq, "no common ancestor for merge")
                    raise BadMergeError("no common ancestor for merge")
                if result_digest is None:
                    self._reject(seq, "three-way merge needs result_digest")
                    raise BadMergeError(
                        "three-way merge needs the host-declared result_digest"
                    )
                try:
                    result_digest = _check_nonempty_str(result_digest, "result_digest")
                except DataVersioningError as exc:
                    self._reject(seq, str(exc))
                    raise
                message = f"Merge branch '{source_branch}' into '{target_branch}'"
                commit_rec = self._mint_commit(
                    repo_id, target_branch, message, result_digest,
                    (tgt_head, src_head), seq,
                )
                record = MergeRecord(
                    merge_id=merge_id,
                    repo_id=repo_id,
                    source_branch=source_branch,
                    target_branch=target_branch,
                    strategy=strategy,
                    fast_forward=False,
                    base_commit_id=base,
                    result_commit_id=commit_rec.commit_id,
                    seq=seq,
                    digest=_pin(
                        [
                            "merge", merge_id, repo_id, source_branch,
                            target_branch, strategy, False, base,
                            commit_rec.commit_id, seq,
                        ],
                        self._seed,
                    ),
                )
            self._merges[merge_id] = record
            self._emit(
                KIND_MERGED,
                seq,
                repo_id=repo_id,
                source_branch=source_branch,
                target_branch=target_branch,
                strategy=strategy,
                fast_forward=record.fast_forward,
                result_commit_id=record.result_commit_id,
            )
            return record

    def tag(
        self, repo_id: str, tag_name: str, commit_id: str, seq: int
    ) -> TagRecord:
        """Book an immutable tag → commit pointer."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                repo_id = _check_name(repo_id, "repo_id")
                tag_name = _check_name(tag_name, "tag_name")
                commit_id = _check_nonempty_str(commit_id, "commit_id")
                self._require_repo(repo_id)
                try:
                    target = self._commits[commit_id]
                except KeyError:
                    raise UnknownCommitError(f"unknown commit: {commit_id!r}")
                if target.repo_id != repo_id:
                    raise BadTagError("commit belongs to another repo")
                if (repo_id, tag_name) in self._tags:
                    raise DuplicateTagError(f"tag already exists: {tag_name!r}")
            except DataVersioningError as exc:
                self._reject(seq, str(exc))
                raise
            record = TagRecord(
                repo_id=repo_id,
                tag=tag_name,
                commit_id=commit_id,
                seq=seq,
                digest=_pin(
                    ["tag", repo_id, tag_name, commit_id, seq], self._seed
                ),
            )
            self._tags[(repo_id, tag_name)] = record
            self._emit(
                KIND_TAGGED, seq, repo_id=repo_id, tag=tag_name, commit_id=commit_id
            )
            return record

    # -- reads (pure views: validate seq shape, consume nothing) ---------

    def repo_record(self, repo_id: str) -> RepoRecord:
        with self._lock:
            return self._require_repo(_check_name(repo_id, "repo_id"))

    def commit_record(self, commit_id: str) -> CommitRecord:
        with self._lock:
            try:
                return self._commits[_check_nonempty_str(commit_id, "commit_id")]
            except KeyError:
                raise UnknownCommitError(f"unknown commit: {commit_id!r}")

    def branch_record(self, repo_id: str, branch: str) -> BranchRecord:
        with self._lock:
            return self._require_branch(
                _check_name(repo_id, "repo_id"), _check_name(branch, "branch")
            )

    def tag_record(self, repo_id: str, tag: str) -> TagRecord:
        with self._lock:
            key = (_check_name(repo_id, "repo_id"), _check_name(tag, "tag"))
            try:
                return self._tags[key]
            except KeyError:
                raise UnknownTagError(f"unknown tag: {tag!r}")

    def head(self, repo_id: str, branch: str) -> Optional[str]:
        """Current head commit id of a branch (``None`` if no commits)."""
        return self.branch_record(repo_id, branch).head_commit_id

    def history(
        self, repo_id: str, branch: str, seq: int, limit: int = 50
    ) -> tuple:
        """Newest-first first-parent walk from the branch head."""
        _check_seq(seq, "seq")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise DataVersioningError("limit must be an int")
        if not 1 <= limit <= _MAX_HISTORY_LIMIT:
            raise DataVersioningError(
                f"limit must be in [1, {_MAX_HISTORY_LIMIT}]"
            )
        with self._lock:
            head = self.branch_record(repo_id, branch).head_commit_id
            out: list = []
            seen: set = set()
            cid = head
            while cid is not None and len(out) < limit and cid not in seen:
                seen.add(cid)
                rec = self._commits[cid]
                out.append(rec)
                cid = rec.parents[0] if rec.parents else None
            return tuple(out)

    def merge_base(
        self, repo_id: str, source_branch: str, target_branch: str, seq: int
    ) -> Optional[str]:
        """Nearest common ancestor of two branch heads (``None`` if none)."""
        _check_seq(seq, "seq")
        with self._lock:
            repo_id = _check_name(repo_id, "repo_id")
            self._require_repo(repo_id)
            src_head = self._require_branch(
                repo_id, _check_name(source_branch, "source_branch")
            ).head_commit_id
            tgt_head = self._require_branch(
                repo_id, _check_name(target_branch, "target_branch")
            ).head_commit_id
            if src_head is None or tgt_head is None:
                return None
            return self._merge_base(tgt_head, src_head)

    def stats(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "repos": len(self._repos),
                "commits": len(self._commits),
                "branches": len(self._branches),
                "tags": len(self._tags),
                "merges": len(self._merges),
                "audit_events": len(self._audit_log),
            }

    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._audit_log)

    def as_dict(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "module": "data_versioning",
                "version": DATA_VERSIONING_VERSION,
                "schema": DATA_VERSIONING_SCHEMA,
                "repos": sorted(self._repos),
                "commits": len(self._commits),
                "last_seq": self._last_seq,
            }


def main() -> None:
    dv = DataVersioning(seed="selfcheck")
    dv.init_repo("ds", 0)
    c1 = dv.commit("ds", "main", "sha256:aaa", "ingest v1", 1)
    assert c1.parents == () and c1.verify(seed="selfcheck")
    dv.branch("ds", "feat", c1.commit_id, 2)
    c2 = dv.commit("ds", "feat", "sha256:bbb", "feature work", 3)
    ff = dv.merge("ds", "feat", "main", 4)
    assert ff.fast_forward is True and ff.result_commit_id == c2.commit_id
    assert dv.head("ds", "main") == c2.commit_id
    c3 = dv.commit("ds", "main", "sha256:ccc", "main work", 5)
    c4 = dv.commit("ds", "feat", "sha256:ddd", "more feature work", 6)
    m = dv.merge("ds", "feat", "main", 7, result_digest="sha256:eee")
    assert m.fast_forward is False and len(m.result_commit_id) > 0
    assert m.verify(seed="selfcheck")
    assert dv.merge_base("ds", "feat", "main", 8) == c4.commit_id
    dv.tag("ds", "v1.0", m.result_commit_id, 9)
    assert len(dv.history("ds", "main", 10)) == 4
    print("data-versioning OK: init, commit, branch, merge, tag, pins, audit")


if __name__ == "__main__":
    main()
