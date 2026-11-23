"""Structured repository tools for the ``northstar code`` product path.

These tools keep common coding operations narrow and auditable.  They do not
replace the generic file tools or Shell: they provide bounded repository views,
an explicitly validated patch mutation, and access to only the verification
commands the host declared before the run began.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from tools import ToolAccessError, ToolContext, ToolInputError, ToolResult, ToolSpec, grep_files

MAX_REPOSITORY_FILES = 8_000
MAX_PATCH_BYTES = 256 * 1024
MAX_GIT_RESULT_BYTES = 256 * 1024
MAX_PLAN_TEXT_CHARS = 4_000


def _schema(properties: dict[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


def _git_environment() -> dict[str, str]:
    """Small deterministic environment for read-only Git plumbing and apply."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run_git(
    ctx: ToolContext,
    arguments: Sequence[str],
    *,
    stdin: bytes | None = None,
    timeout: int = 30,
) -> subprocess.CompletedProcess[bytes]:
    if ctx.sandbox is None:
        raise ToolAccessError("repository tools need a workspace sandbox")
    process = subprocess.run(
        ["git", "-C", str(ctx.sandbox.root_real), *arguments],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
        timeout=timeout,
        check=False,
    )
    if len(process.stdout) + len(process.stderr) > MAX_GIT_RESULT_BYTES:
        raise ToolInputError(
            f"Git output exceeded the {MAX_GIT_RESULT_BYTES}-byte repository-tool cap"
        )
    return process


def _git_error(process: subprocess.CompletedProcess[bytes], operation: str) -> ToolResult:
    detail = (process.stderr or process.stdout).decode("utf-8", errors="replace").strip()
    return ToolResult.error(
        f"{operation} failed (exit {process.returncode}): {detail or 'no diagnostic'}",
        exit_code=process.returncode,
    )


def repo_map(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Return a bounded, deterministic map of tracked and relevant untracked files."""
    requested = int(payload.get("max_files") or min(500, ctx.limits.max_list_entries))
    limit = max(1, min(requested, ctx.limits.max_list_entries, MAX_REPOSITORY_FILES))
    process = _run_git(
        ctx,
        ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
    )
    if process.returncode != 0:
        return _git_error(process, "repository map")
    raw_paths = [item for item in process.stdout.decode("utf-8", errors="replace").split("\0") if item]
    paths = sorted(dict.fromkeys(raw_paths))
    selected = paths[:limit]
    top_level = Counter(path.split("/", 1)[0] for path in paths)
    suffixes = Counter((Path(path).suffix.lower() or "[none]") for path in paths)
    landmarks = [
        path for path in paths
        if Path(path).name.lower() in {
            "agents.md", "cargo.toml", "go.mod", "makefile", "package.json",
            "pyproject.toml", "readme.md", "requirements.txt", "tox.ini",
        }
    ][:40]
    lines = [
        f"files={len(paths)} shown={len(selected)} truncated={'true' if len(paths) > limit else 'false'}",
        "top-level: " + ", ".join(f"{name}({count})" for name, count in top_level.most_common(30)),
        "file-types: " + ", ".join(f"{name}({count})" for name, count in suffixes.most_common(20)),
    ]
    if landmarks:
        lines.append("landmarks: " + ", ".join(landmarks))
    lines.append("files:\n" + "\n".join(selected))
    if len(paths) > limit:
        lines.append(f"[truncated at {limit} files; narrow the task with SearchCode]")
    return ToolResult.ok(
        "\n".join(lines),
        files=len(paths),
        shown=len(selected),
        truncated=len(paths) > limit,
        top_level=dict(top_level.most_common(30)),
        file_types=dict(suffixes.most_common(20)),
        landmarks=landmarks,
    )


def search_code(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Search source text, using literal matching unless regex=true is explicit."""
    query = payload.get("query")
    if not isinstance(query, str) or not query:
        return ToolResult.error("query must be a non-empty string")
    pattern = query if bool(payload.get("regex", False)) else re.escape(query)
    result = grep_files(
        {
            "pattern": pattern,
            "path": payload.get("path", ".") or ".",
            "glob": payload.get("glob", "") or "",
            "ignore_case": bool(payload.get("ignore_case", False)),
            "max_matches": payload.get("max_matches"),
        },
        ctx,
    )
    result.data = {"query": query, "regex": bool(payload.get("regex", False)), **result.data}
    return result


def git_inspect(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Inspect worktree status or its patch against the immutable starting commit."""
    action = payload.get("action", "status")
    path = payload.get("path", "") or ""
    if path:
        resolved = ctx.resolve(path)
        path = ctx.relative(resolved)
    if action == "status":
        arguments = ["status", "--short", "--branch", "--untracked-files=all"]
    elif action == "stat":
        arguments = ["diff", "--stat", "--no-ext-diff", "--no-textconv", "HEAD"]
        if path:
            arguments.extend(("--", path))
    elif action == "diff":
        context_lines = int(payload.get("context_lines", 3))
        context_lines = max(0, min(context_lines, 20))
        arguments = [
            "diff", "--binary", "--no-ext-diff", "--no-textconv",
            f"--unified={context_lines}", "HEAD", "--",
        ]
        if path:
            arguments.append(path)
    else:
        return ToolResult.error("action must be status, stat, or diff")
    process = _run_git(ctx, arguments)
    if process.returncode != 0:
        return _git_error(process, f"git {action}")
    output = process.stdout.decode("utf-8", errors="replace")
    status_changes = [
        line for line in output.splitlines()
        if line.strip() and not line.startswith("##")
    ]
    return ToolResult.ok(
        output or "(no changes)",
        action=action,
        path=path or None,
        bytes=len(process.stdout),
        clean=(not status_changes if action == "status" else not bool(output.strip())),
    )


def submit_plan(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Cross the host-owned plan gate before any code-task effect may run."""
    phases = ctx.service("code_phase_machine")
    if phases is None:
        return ToolResult.error("SubmitPlan is available only inside a northstar code task")
    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return ToolResult.error("summary must be non-empty text")
    if len(summary) > MAX_PLAN_TEXT_CHARS:
        return ToolResult.error(f"summary exceeds {MAX_PLAN_TEXT_CHARS} characters")

    plan: dict[str, Any] = {"summary": summary.strip()}
    for name, limit in (("files", 64), ("steps", 32), ("risks", 32)):
        value = payload.get(name, [])
        if not isinstance(value, list) or len(value) > limit or any(
            not isinstance(item, str) or not item.strip() or len(item) > MAX_PLAN_TEXT_CHARS
            for item in value
        ):
            return ToolResult.error(
                f"{name} must contain at most {limit} non-empty strings of at most "
                f"{MAX_PLAN_TEXT_CHARS} characters"
            )
        plan[name] = [item.strip() for item in value]

    indices = payload.get("check_indices", [])
    commands = tuple(getattr(ctx.service("config"), "verification_commands", ()) or ())
    if not isinstance(indices, list) or len(indices) > 32 or any(
        isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= len(commands)
        for index in indices
    ):
        return ToolResult.error(
            f"check_indices must contain unique declared check indices; this run declares {len(commands)}"
        )
    if len(set(indices)) != len(indices):
        return ToolResult.error("check_indices must not contain duplicates")
    plan["check_indices"] = list(indices)
    try:
        phases.submit_plan(plan)
    except (TypeError, ValueError) as error:
        return ToolResult.error(f"plan refused: {error}")
    return ToolResult.ok(
        "plan accepted; effectful tools may now enter Execute"
        if not phases.plan_only
        else "plan accepted; plan-only task will remain read-only",
        phase=phases.state,
        files=len(plan["files"]),
        steps=len(plan["steps"]),
        risks=len(plan["risks"]),
        check_indices=plan["check_indices"],
    )


def _patch_paths(patch: str) -> tuple[str, ...]:
    """Extract and validate every target from canonical ``diff --git`` headers."""
    if "GIT binary patch" in patch or "Binary files " in patch:
        raise ToolInputError("ApplyPatch accepts text patches only")
    forbidden = (
        "rename from ", "rename to ", "copy from ", "copy to ",
        "new file mode 120000", "new file mode 160000",
        "old mode 120000", "old mode 160000",
        "new mode 120000", "new mode 160000",
    )
    for line in patch.splitlines():
        if line.startswith(forbidden):
            raise ToolInputError("ApplyPatch refuses renames, copies, symlinks, and submodules")
    paths: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("diff --git "):
            continue
        try:
            parts = shlex.split(line)
        except ValueError as error:
            raise ToolInputError(f"malformed diff header: {error}") from error
        if len(parts) != 4 or not parts[2].startswith("a/") or not parts[3].startswith("b/"):
            raise ToolInputError("ApplyPatch requires canonical diff --git a/PATH b/PATH headers")
        old_path, new_path = parts[2][2:], parts[3][2:]
        if old_path != new_path:
            raise ToolInputError("ApplyPatch does not accept rename or copy patches")
        if not old_path or old_path == "/dev/null":
            raise ToolInputError("ApplyPatch found an empty target path")
        paths.append(old_path)
    if not paths:
        raise ToolInputError("ApplyPatch needs at least one diff --git header")
    return tuple(dict.fromkeys(paths))


def apply_patch(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Apply one bounded text patch after every target crosses workspace policy."""
    patch = payload.get("patch")
    if not isinstance(patch, str) or not patch.strip():
        return ToolResult.error("patch must be non-empty text")
    encoded = patch.encode("utf-8")
    if len(encoded) > MAX_PATCH_BYTES:
        return ToolResult.error(f"patch exceeds the {MAX_PATCH_BYTES}-byte ApplyPatch cap")
    try:
        declared_paths = _patch_paths(patch)
        inventory = _run_git(ctx, ("apply", "--numstat", "-z", "-"), stdin=encoded)
        if inventory.returncode != 0:
            return _git_error(inventory, "patch inventory")
        paths: list[str] = []
        for row in inventory.stdout.split(b"\0"):
            if not row:
                continue
            columns = row.split(b"\t", 2)
            if len(columns) != 3:
                raise ToolInputError("patch inventory returned a malformed file record")
            added, deleted, raw_path = columns
            if added == b"-" or deleted == b"-":
                raise ToolInputError("ApplyPatch accepts text patches only")
            path = raw_path.decode("utf-8", errors="strict")
            paths.append(path)
        paths = list(dict.fromkeys(paths))
        if not paths or set(paths) != set(declared_paths):
            raise ToolInputError(
                "patch file inventory does not match its canonical diff headers"
            )
        for path in paths:
            ctx.resolve(path, for_write=True)
    except (ToolAccessError, ToolInputError, UnicodeDecodeError) as error:
        return ToolResult.error(f"patch refused: {error}")
    check = _run_git(
        ctx,
        ("apply", "--check", "--whitespace=nowarn", "--recount", "-"),
        stdin=encoded,
    )
    if check.returncode != 0:
        return _git_error(check, "patch check")
    applied = _run_git(
        ctx,
        ("apply", "--whitespace=nowarn", "--recount", "-"),
        stdin=encoded,
    )
    if applied.returncode != 0:
        return _git_error(applied, "patch apply")
    return ToolResult.ok(
        f"applied patch to {len(paths)} file(s): " + ", ".join(paths),
        paths=list(paths),
        bytes=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
    )


def run_check(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Run one host-declared verification command by index, never model-authored text."""
    config = ctx.service("config")
    commands = tuple(getattr(config, "verification_commands", ()) or ())
    index = payload.get("index")
    if isinstance(index, bool) or not isinstance(index, int):
        return ToolResult.error("index must be an integer")
    if index < 0 or index >= len(commands):
        return ToolResult.error(
            f"check index {index} is out of range; this run declares {len(commands)} check(s)"
        )
    from verification import run_commands

    receipt = run_commands((commands[index],), context=ctx)[0]
    data = receipt.as_dict()
    data["index"] = index
    content = (
        f"check[{index}] {'passed' if receipt.ok else 'failed'}: {commands[index]}\n"
        f"{receipt.output_excerpt}"
    ).rstrip()
    return ToolResult(
        content=content,
        is_error=False,
        truncated=receipt.truncated,
        data=data,
    )


CODE_TOOLS: tuple[str, ...] = (
    "RepoMap",
    "SearchCode",
    "GitInspect",
    "SubmitPlan",
    "ApplyPatch",
    "RunCheck",
)


def code_tool_specs() -> tuple[ToolSpec, ...]:
    """Tool specifications added only for the programming product profile."""
    return (
        ToolSpec(
            name="RepoMap",
            description="Map tracked and relevant untracked repository files with bounded language and directory summaries.",
            input_schema=_schema({"max_files": {"type": "integer", "minimum": 1}}),
            handler=repo_map,
            kind="read",
        ),
        ToolSpec(
            name="SearchCode",
            description="Search workspace source text. Queries are literal unless regex=true; results and scan breadth are capped.",
            input_schema=_schema(
                {
                    "query": {"type": "string"},
                    "path": {"type": "string"},
                    "glob": {"type": "string"},
                    "regex": {"type": "boolean"},
                    "ignore_case": {"type": "boolean"},
                    "max_matches": {"type": "integer", "minimum": 1},
                },
                ("query",),
            ),
            handler=search_code,
            kind="read",
        ),
        ToolSpec(
            name="GitInspect",
            description="Inspect repository status, diff statistics, or the patch against HEAD without invoking external diff drivers.",
            input_schema=_schema(
                {
                    "action": {"type": "string", "enum": ["status", "stat", "diff"]},
                    "path": {"type": "string"},
                    "context_lines": {"type": "integer", "minimum": 0, "maximum": 20},
                }
            ),
            handler=git_inspect,
            kind="read",
        ),
        ToolSpec(
            name="SubmitPlan",
            description=(
                "Submit the structured implementation plan exactly once. Code-task effects "
                "remain gated until this succeeds. check_indices refer only to host-declared checks."
            ),
            input_schema=_schema(
                {
                    "summary": {"type": "string", "minLength": 1, "maxLength": MAX_PLAN_TEXT_CHARS},
                    "files": {
                        "type": "array", "maxItems": 64,
                        "items": {"type": "string", "minLength": 1, "maxLength": MAX_PLAN_TEXT_CHARS},
                    },
                    "steps": {
                        "type": "array", "maxItems": 32,
                        "items": {"type": "string", "minLength": 1, "maxLength": MAX_PLAN_TEXT_CHARS},
                    },
                    "risks": {
                        "type": "array", "maxItems": 32,
                        "items": {"type": "string", "minLength": 1, "maxLength": MAX_PLAN_TEXT_CHARS},
                    },
                    "check_indices": {
                        "type": "array", "maxItems": 32,
                        "items": {"type": "integer", "minimum": 0},
                    },
                },
                ("summary", "files", "steps", "risks", "check_indices"),
            ),
            handler=submit_plan,
            kind="read",
            is_mutating=False,
        ),
        ToolSpec(
            name="ApplyPatch",
            description="Apply a bounded canonical unified text patch after every target crosses workspace and governance-path checks.",
            input_schema=_schema({"patch": {"type": "string"}}, ("patch",)),
            handler=apply_patch,
            kind="edit",
        ),
        ToolSpec(
            name="RunCheck",
            description="Run one host-declared verification command by its zero-based index. Arbitrary command text is not accepted.",
            input_schema=_schema({"index": {"type": "integer", "minimum": 0}}, ("index",)),
            handler=run_check,
            kind="exec",
        ),
    )


__all__ = [
    "CODE_TOOLS",
    "MAX_PATCH_BYTES",
    "apply_patch",
    "code_tool_specs",
    "git_inspect",
    "repo_map",
    "run_check",
    "search_code",
    "submit_plan",
]
