"""Skill-bundled scripts: discoverable, sandboxed, never auto-run.

A skill package may ship helper scripts next to ``SKILL.md``::

    .northstar/skills/<name>/
        SKILL.md
        scripts/
            fetch_notes.py
            summarize.sh

Rules (spine P4 — sandbox-only execution):

1. **Discovery only in the prompt.** The system prompt lists script paths so
   the model knows they exist; nothing is executed at discovery time.
2. **Execution only through ``Shell``**, which is still kind ``exec``, default
   deny, and goes through ``tools.os_sandbox``. There is no "run skill script"
   backdoor that skips the permission gate.
3. **Path containment.** Scripts must resolve inside the workspace skill tree.
   Symlinks that escape the workspace are refused at discovery.
4. **No interpreter injection.** Discovery records the path; the model (or
   operator) chooses argv. We never build ``bash -c "$(curl …)"`` ourselves.
5. **Caps.** A skill may ship a bounded number of scripts; oversized trees are
   truncated in the listing, never silently expanded into the prompt forever.

This module does not register a new tool. Shell already covers execution.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from skills import SKILL_FILE_NAME, SKILLS_DIRECTORY, Skill, SkillError

SCRIPTS_DIRECTORY = "scripts"
MAX_SCRIPTS_PER_SKILL = 16
MAX_SCRIPT_NAME_CHARS = 128
MAX_LISTING_CHARS = 4_000

#: Extensions we will name in the listing. Anything else is ignored (not an error):
#: a skill may keep data files beside scripts without the runtime treating them
#: as runnable.
SCRIPT_SUFFIXES = frozenset({
    ".py", ".sh", ".bash", ".js", ".mjs", ".ts", ".rb", ".pl", ".r",
})

_LISTING_START = "\n\n== Skill scripts (run only via Shell, default-deny) ==\n"
_LISTING_END = "\n== End of skill scripts =="


@dataclass(frozen=True)
class SkillScript:
    """One discovered script file under a skill package."""

    skill: str
    name: str
    relative: str  # workspace-relative path the model can pass to Shell
    path: Path

    def as_dict(self) -> dict[str, str]:
        return {"skill": self.skill, "name": self.name, "path": self.relative}


def discover_skill_scripts(
    workspace: str | Path,
    skills: Iterable[Skill],
) -> tuple[SkillScript, ...]:
    """Walk each skill's ``scripts/`` directory; refuse symlink escapes."""
    root = Path(workspace).resolve()
    found: list[SkillScript] = []
    for skill in skills:
        skill_dir = skill.path.parent
        scripts_dir = skill_dir / SCRIPTS_DIRECTORY
        if not scripts_dir.is_dir():
            continue
        resolved_dir = Path(os.path.realpath(str(scripts_dir)))
        try:
            resolved_dir.relative_to(root)
        except ValueError as error:
            raise SkillError(
                f"skill {skill.name}: scripts/ resolves outside the workspace root {root}; "
                "refusing to follow the symlink"
            ) from error
        entries = sorted(scripts_dir.iterdir(), key=lambda p: p.name)
        count = 0
        for entry in entries:
            if count >= MAX_SCRIPTS_PER_SKILL:
                break
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in SCRIPT_SUFFIXES:
                continue
            if len(entry.name) > MAX_SCRIPT_NAME_CHARS or any(ch in entry.name for ch in "/\\\x00"):
                raise SkillError(f"skill {skill.name}: script name {entry.name!r} is not usable")
            resolved = Path(os.path.realpath(str(entry)))
            try:
                resolved.relative_to(root)
            except ValueError as error:
                raise SkillError(
                    f"skill {skill.name}: script {entry.name} resolves outside the workspace; "
                    "refusing to follow the symlink"
                ) from error
            try:
                relative = str(resolved.relative_to(root))
            except ValueError:
                relative = str(Path(SKILLS_DIRECTORY) / skill.name / SCRIPTS_DIRECTORY / entry.name)
            found.append(
                SkillScript(
                    skill=skill.name,
                    name=entry.name,
                    relative=relative,
                    path=resolved,
                )
            )
            count += 1
    return tuple(found)


def skill_scripts_listing(scripts: Iterable[SkillScript]) -> str:
    """Compose the progressive-disclosure section for skill scripts."""
    items = list(scripts)
    if not items:
        return ""
    bullets: list[str] = []
    for script in items:
        bullets.append(
            f"- {script.skill}/{script.name}: path `{script.relative}` "
            f"(Shell argv preferred; requires --allow-tool Shell)"
        )
    body = "\n".join(bullets)
    if len(body) > MAX_LISTING_CHARS:
        body = body[:MAX_LISTING_CHARS] + "\n[listing truncated]"
    return f"{_LISTING_START}{body}{_LISTING_END}"


__all__ = [
    "MAX_SCRIPTS_PER_SKILL",
    "SCRIPT_SUFFIXES",
    "SCRIPTS_DIRECTORY",
    "SkillScript",
    "discover_skill_scripts",
    "skill_scripts_listing",
]
