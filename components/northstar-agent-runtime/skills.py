"""Workspace Agent Skills discovery (progressive disclosure, read-only).

A skill is a folder ``.northstar/skills/<name>/SKILL.md`` whose frontmatter
carries ``name`` and ``description``. Only the name and description are placed
in the system prompt at startup (a few tokens per skill); the full instructions
live in the file, and the model reads them with the ordinary, sandboxed
``Read`` tool when a task matches - governance never leaves the loop: a skill
file is text, not an execution or permission channel, and anything outside the
workspace root (including a symlinked skill folder) is refused, never followed.

The listing is capped so a large skill collection cannot grow a run's context
without bound.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from frontmatter import FrontmatterError, parse_frontmatter

SKILLS_DIRECTORY = ".northstar/skills"
SKILL_FILE_NAME = "SKILL.md"
MAX_SKILLS = 40
MAX_DESCRIPTION_CHARS = 600
MAX_LISTING_CHARS = 8_000
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

_ALLOWED_KEYS = frozenset({"name", "description", "model"})
_LISTING_START = "\n\n== Workspace skills ==\n"
_LISTING_END = "\n== End of workspace skills =="


class SkillError(ValueError):
    """A workspace skill is unusable. Message is operator-facing."""


@dataclass(frozen=True)
class Skill:
    """One discovered skill package: identity plus the path to read."""

    name: str
    description: str
    path: Path            # absolute path of the SKILL.md inside the workspace
    model: str = ""


def skills_directory(workspace: str | Path) -> Path:
    return Path(workspace) / SKILLS_DIRECTORY


def discover_skills(workspace: str | Path) -> tuple[Skill, ...]:
    """Discover skills under the workspace root; errors are operator-facing."""
    root = Path(workspace).resolve()
    directory = root / SKILLS_DIRECTORY
    if not directory.is_dir():
        return ()
    skills: list[Skill] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_dir():
            continue  # stray files in the skills directory are not skills
        resolved = entry.resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise SkillError(
                f"skill folder {entry} resolves outside the workspace root {root}; "
                "refusing to follow the symlink"
            )
        skill_file = entry / SKILL_FILE_NAME
        if not skill_file.is_file():
            continue  # a folder without SKILL.md is not (yet) a skill
        resolved_file = skill_file.resolve(strict=False)
        if not resolved_file.is_relative_to(root):
            raise SkillError(
                f"skill file {skill_file} resolves outside the workspace root {root}; "
                "refusing to follow the symlink"
            )
        skills.append(_parse_skill(resolved_file))
    return tuple(sorted(skills, key=lambda skill: skill.name))


def _parse_skill(skill_file: Path) -> Skill:
    try:
        raw = skill_file.read_bytes()
    except OSError as error:
        raise SkillError(f"{skill_file}: cannot read skill: {error}") from error
    try:
        fields, _body = parse_frontmatter(raw.decode("utf-8", errors="replace"))
    except FrontmatterError as error:
        raise SkillError(f"{skill_file}: {error}") from error
    if fields is None:
        raise SkillError(f"{skill_file}: a skill needs YAML frontmatter (name and description)")
    unknown = sorted(set(fields) - _ALLOWED_KEYS)
    if unknown:
        raise SkillError(
            f"{skill_file}: unknown key(s) {', '.join(unknown)} - allowed: {', '.join(sorted(_ALLOWED_KEYS))}"
        )
    name = fields.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise SkillError(f"{skill_file}: name must be a lowercase identifier matching {_NAME_RE.pattern!r}")
    description = fields.get("description")
    if not isinstance(description, str) or not description.strip():
        raise SkillError(f"{skill_file}: description is required (this is the trigger text the model sees)")
    model = fields.get("model", "")
    if not isinstance(model, str):
        raise SkillError(f"{skill_file}: model must be a string")
    return Skill(
        name=name,
        description=description.strip()[:MAX_DESCRIPTION_CHARS],
        path=skill_file.resolve(),
        model=model,
    )


def skill_listing(skills: Iterable[Skill], workspace: str | Path) -> str:
    """Compose the progressive-disclosure section for the system prompt."""
    root = Path(workspace).resolve()
    bullets: list[str] = []
    for skill in skills:
        relative = skill.path.relative_to(root)
        bullets.append(f"- {skill.name}: {skill.description}  (Read '{relative}' for full instructions)")
    body = "\n".join(bullets)
    if len(body) > MAX_LISTING_CHARS:
        body = body[:MAX_LISTING_CHARS] + "\n[listing truncated]"
    return f"{_LISTING_START}{body}{_LISTING_END}"
