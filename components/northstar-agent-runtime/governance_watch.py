"""Governance-tree drift watch: what the exec path could not be stopped from doing.

Why this exists
---------------
The permission gate decides *whether* a tool call runs. It cannot decide what an
approved call does afterwards. ``Shell`` is the clearest case: the file tools refuse
writes under ``.northstar`` and ``.git`` (:class:`tools.ToolSandbox`), while a
``Shell`` payload only has to keep its ``cwd`` inside the workspace — so one granted
``Shell`` call can drop ``deny_tools`` from the run's own policy file, plant an
instruction in ``skills/*/SKILL.md``, or add ``[alias]`` to ``.git/config`` and have the
*host* execute it later. ``os_sandbox`` closes this on the ``bwrap`` backend (the
governance tree is bound read-only, see :func:`tools.os_sandbox._bwrap_argv`); no user
namespace can be bound on the ``process`` backend, so a fallback run needs a different
answer. This module is that answer: **freeze, re-check after every exec, leave evidence,
end the run.**

What is watched, and why that is not everything
-----------------------------------------------
Exactly what the write gate protects, minus what the runtime or its carve-outs write on
purpose:

* ``.northstar/**`` — policy, agent definitions, skills, plugin locks and bundles;
* ``.git/config``, ``.git/config.local``, ``.git/info/exclude``, ``.git/hooks/**`` —
  the git files whose *contents* make something execute or get trusted.

``.git`` is deliberately narrowed: any legitimate ``git add``/``git commit`` inside a
sandbox rewrites ``index``, ``objects`` and ``logs``, so watching the whole tree would
train operators to ignore the finding. Everything under
``.northstar/memory`` (the sanctioned carve-out), ``.northstar/tmp`` (the sandbox
scratch dir) and ``.northstar/sessions`` (the transcript this run is appending to) is
ignored, and the ignore list is reported in the audit record so a reader can see the
blind spot instead of guessing it.

Honest limits
-------------
- **Detection, not prevention.** The bytes have already changed when the drift is
  reported; the run is stopped before it can *benefit* from them (no further turns, no
  ``success``), and the transcript carries the evidence. Prevention is the ``bwrap``
  read-only bind; on a host without it, a hostile payload with a single-shot
  side effect can still win.
- **Not a signature.** A fingerprint is a digest of content the operator could have
  written themselves; it detects the agent's edit and the accidental one, not a
  determined host-side attacker who can rewrite both the tree and this run's memory.
- **Bounded**: entry count and file size caps below; a file too large to hash is
  fingerprinted by size + name, and says so.
- Only the **top-level** run watches: subagents share the parent's workspace, so a child
  checking the same tree would double the cost and attribute the finding to the wrong
  transcript.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: Identity of the watch's rules, so a transcript can say which shape produced a finding.
GUARD_VERSION = "northstar.governance.watch.v1"

#: Prefixes watched when the caller does not narrow them — mirrored from
#: ``tools.ToolLimits.protected_prefixes`` at construction, never invented here.
DEFAULT_PREFIXES: tuple[str, ...] = (".northstar", ".git")

#: Subtrees under a watched prefix that the runtime or a documented carve-out writes on
#: purpose. Kept in one place so the audit record can print its own blind spot.
IGNORED_RELATIVES: tuple[str, ...] = (
    ".northstar/memory",
    ".northstar/tmp",
    ".northstar/sessions",
)

#: Under ``.git`` only these are execution-bearing; everything else churns during normal
#: use (see the module docstring). ``hooks`` is a directory: its whole subtree counts.
GIT_WATCH_NAMES: tuple[str, ...] = ("config", "config.local", "info/exclude", "hooks")

#: Cost ceilings: the watch must never become the most expensive part of a run.
MAX_ENTRIES = 2_000
MAX_HASH_BYTES = 4 * 1024 * 1024


class GovernanceWatchError(ValueError):
    """The watch cannot be built. A configuration error, never a silent no-op."""


@dataclass(frozen=True)
class GovernanceSnapshot:
    """One frozen view of the governance tree: relative path -> fingerprint."""

    items: Mapping[str, str] = field(default_factory=dict)
    version: str = GUARD_VERSION
    truncated: bool = False

    @property
    def watched(self) -> int:
        return len(self.items)

    @property
    def digest(self) -> str:
        """A single key for the whole tree, so a transcript can compare two runs cheaply."""
        canonical = "\n".join(f"{name}\t{self.items[name]}" for name in sorted(self.items))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "watched": self.watched,
            "digest": self.digest,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class DriftReport:
    """What changed between a frozen snapshot and the tree as it is now."""

    changed: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    watched: int = 0
    truncated: bool = False
    version: str = GUARD_VERSION
    #: The two tree digests, in the record itself: "which run, against which baseline" is the
    #: first question an operator asks, and making them open the transcripts again is rude.
    before: str = ""
    after: str = ""

    @property
    def ok(self) -> bool:
        return not (self.changed or self.added or self.removed)

    @property
    def findings(self) -> tuple[str, ...]:
        return tuple(f"changed:{name}" for name in self.changed) + tuple(
            f"added:{name}" for name in self.added
        ) + tuple(f"removed:{name}" for name in self.removed)

    def summary(self) -> str:
        parts = [f"{len(self.changed)} changed", f"{len(self.added)} added", f"{len(self.removed)} removed"]
        tail = f" of {self.watched} watched"
        if self.truncated:
            tail += " (tree larger than the watch's entry cap)"
        return ", ".join(parts) + tail

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "ok": self.ok,
            "changed": list(self.changed),
            "added": list(self.added),
            "removed": list(self.removed),
            "watched": self.watched,
            "truncated": self.truncated,
            "before": self.before,
            "after": self.after,
            "summary": self.summary(),
        }


def _fingerprint(path: Path) -> str:
    """A content key for one entry: digest, symlink target, or a named fallback."""
    if path.is_symlink():
        try:
            return "symlink->" + os.readlink(str(path))
        except OSError:
            return "symlink-unreadable"
    if path.is_dir():
        return "directory"
    try:
        size = path.stat().st_size
    except OSError:
        return "unreadable"
    if size > MAX_HASH_BYTES:
        # Enough to notice a rewrite of a huge governance file without reading it all.
        return f"oversized:{size}"
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            remaining = MAX_HASH_BYTES
            while remaining > 0:
                chunk = handle.read(min(65_536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def _watch_roots(workspace: Path, prefixes: Sequence[str]) -> list[tuple[Path, str | None]]:
    """(directory, name filter) pairs to walk. ``None`` means "everything inside"."""
    roots: list[tuple[Path, str | None]] = []
    for prefix in prefixes:
        head = Path(prefix).parts[0] if prefix else ""
        if not head:
            raise GovernanceWatchError(f"watch prefix {prefix!r} does not name a directory")
        if head == ".git":
            # Only the named entries (and hooks/**) below .git, never the whole object store.
            roots.append((workspace / head, "git"))
        else:
            roots.append((workspace / head, None))
    return roots


def _walk(root: Path, subset: str | None, out: dict[str, str], *, relative_to: Path) -> None:
    if not root.exists():
        # "Absent at freeze time" is itself information: creating the file later is drift
        # (the exact shape of the 2026 Claude Code settings.json class), so record it.
        out[root.relative_to(relative_to).as_posix()] = "absent"
        return
    if subset == "git":
        for name in GIT_WATCH_NAMES:
            candidate = root / name
            if name == "hooks" and candidate.is_dir():
                for entry in sorted(candidate.rglob("*")):
                    if entry.is_file() or entry.is_symlink():
                        out[entry.relative_to(relative_to).as_posix()] = _fingerprint(entry)
                continue
            if candidate.is_dir():
                continue
            out[candidate.relative_to(relative_to).as_posix()] = _fingerprint(candidate)
        return
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(relative_to).as_posix()
        if any(relative == skip or relative.startswith(skip + "/") for skip in IGNORED_RELATIVES):
            continue
        if entry.is_dir():
            continue
        out[relative] = _fingerprint(entry)
        if len(out) >= MAX_ENTRIES:
            return


def snapshot(
    workspace: str | os.PathLike[str],
    *,
    prefixes: Iterable[str] = DEFAULT_PREFIXES,
) -> GovernanceSnapshot:
    """Freeze the governance tree: every watched path with a content fingerprint."""
    root = Path(os.path.realpath(str(workspace)))
    if not root.is_dir():
        raise GovernanceWatchError(f"workspace is not a directory: {root}")
    chosen = tuple(dict.fromkeys(str(prefix).strip("/") for prefix in prefixes if str(prefix).strip("/")))
    if not chosen:
        raise GovernanceWatchError("nothing to watch: no protected prefixes")
    items: dict[str, str] = {}
    truncated = False
    for directory, subset in _watch_roots(root, chosen):
        _walk(directory, subset, items, relative_to=root)
        if len(items) >= MAX_ENTRIES:
            truncated = True
            break
    return GovernanceSnapshot(items=items, truncated=truncated)


def compare(
    workspace: str | os.PathLike[str],
    before: GovernanceSnapshot,
    *,
    prefixes: Iterable[str] = DEFAULT_PREFIXES,
) -> DriftReport:
    """Re-read the tree and diff it against ``before``. Never raises for a missing file."""
    now = snapshot(workspace, prefixes=prefixes)
    known_before = set(before.items)
    known_now = set(now.items)
    changed = tuple(sorted(name for name in known_before & known_now if before.items[name] != now.items[name]))
    added = tuple(sorted(known_now - known_before))
    # A path recorded as "absent" that is still absent is not a removal; a watched root
    # that vanished entirely (someone deleted .northstar) is.
    removed = tuple(
        sorted(
            name
            for name in known_before - known_now
            if not before.items[name] == "absent"
        )
    )
    return DriftReport(
        changed=changed,
        added=added,
        removed=removed,
        watched=now.watched,
        truncated=before.truncated or now.truncated,
        before=before.digest,
        after=now.digest,
    )


class GovernanceWatch:
    """The small object the loop holds: freeze once, ask after each exec."""

    def __init__(
        self,
        workspace: str | os.PathLike[str],
        *,
        prefixes: Iterable[str] = DEFAULT_PREFIXES,
        enabled: bool = True,
    ) -> None:
        self.workspace = Path(workspace)
        self.prefixes = tuple(dict.fromkeys(str(prefix).strip("/") for prefix in prefixes if str(prefix).strip("/")))
        self.enabled = bool(enabled)
        self._before: GovernanceSnapshot | None = None
        self._error: str = ""

    # -- lifecycle ---------------------------------------------------------
    def freeze(self) -> GovernanceSnapshot | None:
        """Take the baseline. A disabled watch returns ``None`` and never raises."""
        if not self.enabled:
            return None
        try:
            self._before = snapshot(self.workspace, prefixes=self.prefixes)
        except GovernanceWatchError as error:
            # The watch itself must not be the thing that kills a run: an unusable
            # workspace is reported once in the audit and the run proceeds ungated.
            self._error = str(error)
            self._before = None
        return self._before

    @property
    def snapshot(self) -> GovernanceSnapshot | None:
        return self._before

    @property
    def frozen(self) -> bool:
        return self._before is not None

    # -- verdict -----------------------------------------------------------
    def check(self) -> DriftReport | None:
        """``None`` when there is nothing to say (off, unfrozen, or no drift)."""
        if not self.enabled or self._before is None:
            return None
        report = compare(self.workspace, self._before, prefixes=self.prefixes)
        return None if report.ok else report

    def describe(self) -> dict[str, Any]:
        """What the loop puts in the ``init`` record — including its own blind spot."""
        data: dict[str, Any] = {
            "version": GUARD_VERSION,
            "enabled": self.enabled,
            "prefixes": list(self.prefixes),
            "ignored": list(IGNORED_RELATIVES),
            "git_subset": list(GIT_WATCH_NAMES),
        }
        if self._before is not None:
            data["baseline"] = self._before.as_dict()
        if self._error:
            data["error"] = self._error
        if not self.enabled:
            data["reason"] = "the operator passed --no-drift-check; nothing here will notice a rewrite"
        return data


__all__ = [
    "DEFAULT_PREFIXES",
    "GIT_WATCH_NAMES",
    "GUARD_VERSION",
    "IGNORED_RELATIVES",
    "MAX_ENTRIES",
    "MAX_HASH_BYTES",
    "DriftReport",
    "GovernanceSnapshot",
    "GovernanceWatch",
    "GovernanceWatchError",
    "compare",
    "snapshot",
]
