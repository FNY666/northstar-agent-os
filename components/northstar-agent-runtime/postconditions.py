"""Postconditions: an independent verdict on whether the work actually happened.

Why this exists
---------------
A run that ends ``success`` means only that the model stopped asking for tools. The
2026-09 audit of the market leaders found the same shape everywhere (Codex reports
``turn.completed`` unconditionally, Cursor prints "looks done", Claude Code's
completion depends on the Stop hook you did not write), and Northstar had no answer
either: ``stop_reason=end_turn`` was the whole definition of done.

A postcondition is a claim about the *workspace* that is checked by this process,
not by the model, at the end of the run:

``exists`` / ``absent``      a path is present / not present
``changed``                  its bytes differ from the pre-run snapshot (a file the
                             run created counts as changed)
``unchanged``                its bytes are identical to the pre-run snapshot - the
                             check that makes "read-only review" enforceable
``contains``                 the text appears in the file at least ``count`` times

Honest limits, because a verification story without them is marketing
---------------------------------------------------------------------
- The conditions are **never injected into the system prompt**. Telling the model
  what will be checked converts the check into a target, and content checks are the
  easiest thing in the world to satisfy by writing the expected string. They live in
  the config and the audit stream, and the model is not consulted.
- That also means ``contains`` is a convenience, not a proof of semantics. The
  enforceable claims are the structural ones (exists/absent/changed/unchanged). For
  "the tests actually pass", declare a ``Stop`` hook running the test script - it
  can veto finishing, and it is a vetted script rather than a shell string.
- Only reading happens: no writes, no execution, no network. Paths must resolve
  inside the workspace, because evidence from outside the sandbox boundary is not
  evidence about this run.
- A run that ends on a ceiling, a denial, a compaction failure or a provider error
  already carries a failing subtype; the verdict is still recorded for the audit, but
  it does not overwrite the reason the run stopped. Only a would-be ``success`` can
  be demoted, to ``error_postconditions_failed``.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: Every kind a postcondition can take. Unknown kinds are configuration errors,
#: never warnings: a check that silently does not run is worse than no check.
KINDS: tuple[str, ...] = ("exists", "absent", "changed", "unchanged", "contains")

#: Kinds whose verdict is about the world rather than about text the model could
#: have written to please us. ``summarise`` reports this split.
STRUCTURAL_KINDS: frozenset[str] = frozenset({"exists", "absent", "changed", "unchanged"})

#: Cap the digest work: a workspace with a multi-gigabyte artifact should not make
#: verification the most expensive part of the run.
MAX_DIGEST_BYTES = 64 * 1024 * 1024


class PostConditionError(ValueError):
    """Raised for a malformed, unknown, or out-of-bounds postcondition."""


def _digest(path: Path) -> str | None:
    """Content address of a file, or ``None`` when it does not exist as a file.

    A symlink is refused rather than followed to an outside target: the digest has to
    describe bytes *inside* the workspace, or the comparison proves nothing.
    """
    if not path.exists():
        return None
    if path.is_symlink():
        # A symlink's content lives wherever it points, so its digest would be
        # evidence about some other directory than the one under review.
        raise PostConditionError(f"{path.name} is a symlink: postconditions read regular files inside the workspace only")
    if not path.is_file():
        raise PostConditionError(f"{path.name} is not a regular file inside the workspace")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            remaining = MAX_DIGEST_BYTES
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError as error:
        raise PostConditionError(f"cannot read {path.name}: {error}") from error
    return digest.hexdigest()


@dataclass(frozen=True)
class PostCondition:
    """One claim about the workspace, evaluated after the run."""

    kind: str
    path: str
    text: str = ""
    count: int = 1

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise PostConditionError(f"unknown postcondition kind {self.kind!r}; expected one of {', '.join(KINDS)}")
        path = (self.path or "").strip()
        if not path:
            raise PostConditionError("a postcondition needs a path")
        if path.startswith("/") or path == ".." or path.startswith("../"):
            raise PostConditionError(f"postcondition path {path!r} must be workspace-relative, not absolute or escaping")
        object.__setattr__(self, "path", path)
        if self.kind == "contains" and not self.text.strip():
            raise PostConditionError("a 'contains' postcondition needs the text to look for")
        if self.count < 1:
            raise PostConditionError("count must be >= 1")

    @property
    def structural(self) -> bool:
        return self.kind in STRUCTURAL_KINDS

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"kind": self.kind, "path": self.path}
        if self.kind == "contains":
            # The text is reported so the audit explains the verdict, but it is kept
            # out of anything the model reads.
            data["text"] = self.text
            data["count"] = self.count
        return data


@dataclass(frozen=True)
class Verdict:
    """The outcome of evaluating one postcondition."""

    condition: PostCondition
    ok: bool
    detail: str
    before: str | None
    after: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.condition.as_dict(),
            "ok": self.ok,
            "detail": self.detail,
            "structural": self.condition.structural,
            "digest_before": self.before[:12] if self.before else None,
            "digest_after": self.after[:12] if self.after else None,
        }


def parse_postconditions(entries: Iterable[Mapping[str, Any]], *, source: str = "config") -> tuple[PostCondition, ...]:
    """Validate hook-style mappings into postconditions, rejecting anything else."""
    parsed: list[PostCondition] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PostConditionError(f"{source}: postcondition {index} must be a table")
        keys = set(entry) - {"kind", "path", "text", "count"}
        if keys:
            raise PostConditionError(f"{source}: postcondition {index} uses unknown key(s): {', '.join(sorted(keys))}")
        extra = {"text": entry.get("text", ""), "count": int(entry.get("count", 1) or 1)}
        try:
            parsed.append(
                PostCondition(
                    kind=str(entry.get("kind", "")),
                    path=str(entry.get("path", "")),
                    **extra,
                )
            )
        except (PostConditionError, TypeError, ValueError) as error:
            raise PostConditionError(f"{source}: postcondition {index}: {error}") from error
    return tuple(parsed)


def parse_cli_specs(specs: Sequence[str]) -> tuple[PostCondition, ...]:
    """``--verify KIND:PATH`` (and ``contains:PATH:TEXT``) into postconditions."""
    parsed: list[PostCondition] = []
    for spec in specs:
        parts = str(spec).split(":", 2)
        if len(parts) < 2:
            raise PostConditionError(f"--verify expects KIND:PATH (got {spec!r}); kinds: {', '.join(KINDS)}")
        kind, path = parts[0].strip(), parts[1].strip()
        text = parts[2] if len(parts) > 2 else ""
        parsed.append(PostCondition(kind=kind, path=path, text=text))
    return tuple(parsed)


class PostConditionSet:
    """A snapshot-and-compare verifier bound to one workspace."""

    def __init__(self, root: Path | str, conditions: Sequence[PostCondition]) -> None:
        self.root = Path(root).resolve()
        self.conditions = tuple(conditions)
        self._before: dict[str, str | None] | None = None
        for condition in self.conditions:
            self._resolve(condition.path)  # validated eagerly: a bad check is a config error

    def __bool__(self) -> bool:
        return bool(self.conditions)

    def _resolve(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as error:
            raise PostConditionError(f"postcondition path {relative!r} escapes the workspace") from error
        return candidate

    def snapshot(self) -> None:
        """Record pre-run content addresses. Called before the first turn, never after."""
        self._before = {condition.path: _digest(self._resolve(condition.path)) for condition in self.conditions}

    def evaluate(self) -> list[Verdict]:
        if self._before is None:  # pragma: no cover - defensive, the loop always snapshots
            self.snapshot()
        return [self._evaluate_one(condition) for condition in self.conditions]

    def _evaluate_one(self, condition: PostCondition) -> Verdict:
        path = self._resolve(condition.path)
        before = (self._before or {}).get(condition.path)
        after = _digest(path)
        exists = after is not None
        verdict_ok = False
        detail = ""
        if condition.kind == "exists":
            verdict_ok = exists
            detail = "present" if exists else "missing"
        elif condition.kind == "absent":
            verdict_ok = not exists
            detail = "absent as required" if not exists else "still present"
        elif condition.kind == "changed":
            verdict_ok = exists and after != before
            detail = (
                "content differs from the pre-run snapshot"
                if verdict_ok
                else ("unchanged" if exists else "never created")
            )
        elif condition.kind == "unchanged":
            verdict_ok = before == after
            detail = "identical to the pre-run snapshot" if verdict_ok else "was modified"
        else:  # contains
            if not exists:
                detail = "file missing, so nothing contains the expected text"
            else:
                try:
                    body = path.read_text(encoding="utf-8", errors="replace")
                except OSError as error:  # pragma: no cover - unreadable file
                    detail = f"cannot read: {error}"
                    body = ""
                found = body.count(condition.text)
                verdict_ok = found >= condition.count
                detail = f"{found} occurrence(s) of the expected text, need {condition.count}"
        return Verdict(condition=condition, ok=verdict_ok, detail=detail, before=before, after=after)


def summarise(verdicts: Sequence[Verdict]) -> dict[str, Any]:
    """The audit shape: a pass/fail roll-up with the structural split made visible."""
    payload = {
        "checked": len(verdicts),
        "passed": sum(1 for verdict in verdicts if verdict.ok),
        "failed": sum(1 for verdict in verdicts if not verdict.ok),
        "structural_passed": sum(1 for verdict in verdicts if verdict.ok and verdict.condition.structural),
        "results": [verdict.as_dict() for verdict in verdicts],
    }
    payload["ok"] = payload["failed"] == 0
    return payload
