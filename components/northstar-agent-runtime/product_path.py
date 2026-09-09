"""Product defaults for the next-gen Agent OS entry path.

The kernel CLI (``run``) stays flag-explicit so embedding and CI never inherit
hidden behaviour. The product path (``agent`` / ``resume``) is the opposite:
it **welds** the defaults a governed coworker needs so a human does not have
to rediscover ``--session-dir`` and ``--checkpoint-turns`` on every invocation.

Defaults (deliberately boring, deliberately local):

* session transcripts land under ``<workspace>/.northstar/sessions`` unless the
  operator passes ``--session-dir`` (or ``--no-session`` to opt out of audit);
* a resumable checkpoint is written on **every** turn boundary
  (``checkpoint_turns=1``) unless the operator sets ``--checkpoint-turns`` or
  ``--no-checkpoint``;
* ``resume`` **forks** from the parent session's latest checkpoint
  (``--resume-from``), inheriting consumed turns / tool calls / cost so ceilings
  bind the lineage — never the budget-laundering append path (``--resume``);
* nothing else is implied — permission mode, tools, provider, ceilings and
  hooks keep the same fail-closed semantics as ``run``.

These helpers are pure: they only rewrite argv. The loop, the gate and the
session store do not know "product mode" exists, which is the point — a
second semantic surface would be a second place the gate could be wrong.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

#: Directory name under the workspace where product runs keep transcripts.
DEFAULT_SESSION_SUBDIR = ".northstar/sessions"

#: Checkpoint cadence the product path turns on when the operator is silent.
#: ``1`` = every turn boundary; resumable without the operator remembering a flag.
DEFAULT_CHECKPOINT_TURNS = 1

#: Magic session ids the product resume path resolves against the session dir.
LATEST_SESSION_ALIASES = frozenset({"latest", "@latest", "."})


def default_session_dir(workspace: str | Path) -> Path:
    """Absolute path of the product-default session directory for ``workspace``."""
    return (Path(workspace) / DEFAULT_SESSION_SUBDIR).resolve()


def _flag_present(argv: Sequence[str], *names: str) -> bool:
    """True when any of ``names`` appears as a free flag (not a value)."""
    wanted = set(names)
    return any(item in wanted for item in argv)


def _flag_value(argv: Sequence[str], name: str) -> str | None:
    """Return the value bound to ``name`` (``--name VALUE`` or ``--name=VALUE``)."""
    equals = name + "="
    for index, item in enumerate(argv):
        if item == name and index + 1 < len(argv):
            return argv[index + 1]
        if item.startswith(equals):
            return item[len(equals) :]
    return None


def resolve_workspace(argv: Sequence[str]) -> str:
    """Workspace a product invocation will confine tools to (mirrors CLI default)."""
    return _flag_value(argv, "--workspace") or "."


def resolve_session_dir(argv: Sequence[str], *, workspace: str | Path | None = None) -> Path:
    """Session directory a product invocation will read/write.

    Operator ``--session-dir`` wins; otherwise the product default under the
    workspace. Pure path math — does not create the directory.
    """
    explicit = _flag_value(argv, "--session-dir")
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = workspace if workspace is not None else resolve_workspace(argv)
    return default_session_dir(root)


def resolve_session_id(session_id: str, session_dir: str | Path) -> str:
    """Resolve ``latest`` (and aliases) to a concrete session id, or pass through.

    ``latest`` means the most recently modified ``*.jsonl`` in ``session_dir``.
    A missing directory or empty directory is a configuration error — never a
    silently invented id.
    """
    raw = (session_id or "").strip()
    if not raw:
        raise ValueError("resume: session id must be a non-empty string")
    if raw not in LATEST_SESSION_ALIASES:
        if any(ch.isspace() or ch in "/\\" for ch in raw):
            raise ValueError(
                f"resume: session id {raw!r} must not contain whitespace or path separators"
            )
        return raw

    directory = Path(session_dir)
    if not directory.is_dir():
        raise ValueError(
            f"resume: no session directory at {directory} "
            f"(run `northstar agent` first, or pass --session-dir)"
        )
    candidates = [path for path in directory.glob("*.jsonl") if path.is_file()]
    if not candidates:
        raise ValueError(
            f"resume: no transcripts in {directory} "
            f"(nothing to continue; start with `northstar agent`)"
        )
    # mtime then name: stable when two files share a stamp.
    newest = max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name))
    return newest.stem


def _flags_taking_value() -> frozenset[str]:
    """Flags on the agent/run surface whose next argv token is a value, not a task.

    Kept local and conservative: only names the product path itself forwards.
    Unknown ``--flag value`` pairs still consume the value via the leading-dash
    rule below so a bare task cannot steal them.
    """
    return frozenset(
        {
            "--workspace",
            "--prompt",
            "--prompt-file",
            "--provider",
            "--model",
            "--system-prompt",
            "--script",
            "--scripted-text",
            "--session-dir",
            "--session-id",
            "--checkpoint-turns",
            "--max-turns",
            "--max-tool-calls",
            "--max-budget-usd",
            "--max-subagent-depth",
            "--compaction-threshold-tokens",
            "--permission-mode",
            "--allow-tool",
            "--deny-tool",
            "--agent",
            "--sidecar-socket",
            "--sidecar-timeout-ms",
            "--sandbox",
            "--shell-backend",
            "--parallel-tools",
            "--resume",
            "--resume-from",
            "--context-file",
            "--memory-file",
            "--mcp-config",
            "--mcp-protocol",
            "--mcp-elicit-answers",
            "--mcp-max-rounds",
            "--run-id",
            "--verify",
            "--plugin-fail-on",
            "--trace-file",
            "--output-format",
        }
    )


def extract_positional_task(argv: Sequence[str]) -> tuple[list[str], str]:
    """Pull a bare task string out of product ``agent`` argv.

    ``northstar agent "summarise README"`` is the minimal-interaction form of
    ``northstar agent --prompt "summarise README"``. Everything that looks like
    a flag (leading ``-``) stays put; the first non-flag token that is not the
    value of a known flag becomes the task. Multiple bare tokens are a usage
    error — the task is one string, not an argv join.
    """
    flags_with_value = _flags_taking_value()
    out: list[str] = []
    task = ""
    i = 0
    # Skip the leading ``agent`` verb if a caller passed a full argv.
    if argv and argv[0] == "agent":
        i = 1
    while i < len(argv):
        item = argv[i]
        if item == "--":
            # Explicit end-of-flags: the rest is the task (joined).
            rest = list(argv[i + 1 :])
            if rest:
                if task:
                    raise ValueError("agent: pass either a positional task or --prompt, not both forms twice")
                task = " ".join(rest)
            break
        if item.startswith("-"):
            out.append(item)
            name = item.split("=", 1)[0]
            if "=" not in item and name in flags_with_value and i + 1 < len(argv):
                out.append(argv[i + 1])
                i += 2
                continue
            i += 1
            continue
        # Bare token.
        if task:
            raise ValueError(
                "agent: multiple positional task tokens; "
                "quote the task as one string or pass --prompt"
            )
        task = item
        i += 1
    return out, task


def apply_agent_defaults(argv: Sequence[str]) -> list[str]:
    """Rewrite product ``agent`` argv into a ``run`` argv with welded defaults.

    Strips product-only flags (``--no-session``, ``--no-checkpoint``) and injects
    ``--session-dir`` / ``--checkpoint-turns`` when the operator did not set them.
    A bare positional task becomes ``--prompt``. Never loosens a ceiling, never
    adds an allow-list, never enables hooks.
    """
    body, positional = extract_positional_task(list(argv))
    workspace = resolve_workspace(body)
    out: list[str] = []
    no_session = False
    no_checkpoint = False
    for item in body:
        if item in ("--no-session", "--no-checkpoint"):
            if item == "--no-session":
                no_session = True
            else:
                no_checkpoint = True
            continue
        # --in-place is resume-only; ignore if someone pastes it onto agent.
        if item == "--in-place":
            continue
        out.append(item)

    if positional:
        if _flag_present(out, "--prompt") or _flag_present(out, "--prompt-file"):
            raise ValueError(
                "agent: positional task cannot be combined with --prompt / --prompt-file"
            )
        out.extend(["--prompt", positional])

    has_session_dir = _flag_present(out, "--session-dir")
    has_checkpoint = _flag_present(out, "--checkpoint-turns")

    if not no_session and not has_session_dir:
        out.extend(["--session-dir", str(default_session_dir(workspace))])
    if not no_checkpoint and not has_checkpoint:
        out.extend(["--checkpoint-turns", str(DEFAULT_CHECKPOINT_TURNS)])
    return out


def apply_resume_defaults(
    argv: Sequence[str],
    *,
    session_id: str,
    workspace: str | None = None,
) -> list[str]:
    """Rewrite product ``resume`` argv into a governed ``run --resume-from`` argv.

    Product resume **forks** from a checkpoint (``--resume-from``):

    * the parent transcript is never modified (append-only audit stays true);
    * consumed turns / tool calls / cost are inherited so ceilings bind the
      lineage (the bug the checkpoint module exists to close);
    * the child gets a new session id and keeps writing checkpoints.

    Pass ``latest`` (or ``@latest`` / ``.``) as the session id to continue the
    most recently modified transcript in the product session directory.

    ``--in-place`` opts into the low-level append path (``--resume``) for hosts
    that deliberately want the same file; it does **not** inherit checkpoint
    counters — prefer the default fork whenever ceilings matter.
    """
    body = list(argv)
    if workspace and not _flag_present(body, "--workspace"):
        body = ["--workspace", workspace, *body]

    in_place = False
    cleaned: list[str] = []
    for item in body:
        if item == "--in-place":
            in_place = True
            continue
        cleaned.append(item)

    welded = apply_agent_defaults(cleaned)

    if _flag_present(welded, "--resume", "--resume-from"):
        raise ValueError(
            "resume: pass the session id as the positional argument; "
            "--resume / --resume-from are reserved for the low-level run path"
        )

    # Session dir must exist in the welded argv for both fork and append, so the
    # kernel can find the parent transcript. apply_agent_defaults already injects
    # it unless --no-session was set — resume without a transcript is nonsense.
    if not _flag_present(welded, "--session-dir"):
        raise ValueError(
            "resume: needs a session directory (omit --no-session, or pass --session-dir)"
        )
    session_dir = Path(_flag_value(welded, "--session-dir") or "")
    resolved = resolve_session_id(session_id, session_dir)

    if in_place:
        # Low-level append: same file, no counter inheritance. Documented escape.
        return [*welded, "--resume", resolved]
    # Product default: fork-on-read from the latest (or named) checkpoint.
    return [*welded, "--resume-from", resolved]


__all__ = [
    "DEFAULT_CHECKPOINT_TURNS",
    "DEFAULT_SESSION_SUBDIR",
    "LATEST_SESSION_ALIASES",
    "apply_agent_defaults",
    "apply_resume_defaults",
    "default_session_dir",
    "extract_positional_task",
    "resolve_session_dir",
    "resolve_session_id",
    "resolve_workspace",
]
