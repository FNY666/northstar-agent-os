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

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

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


def discover_skills(
    workspace: str | Path,
    *,
    extra_roots: Iterable[str | Path] = (),
    reviewed_digests: Mapping[str, str] | None = None,
    extra_digests: Mapping[str, str] | None = None,
) -> tuple[Skill, ...]:
    """Discover skills under the workspace root; errors are operator-facing.

    ``extra_roots`` is the seam an installed plugin bundle uses: each entry is a directory
    whose children are skill folders, exactly like ``.northstar/skills``. It is checked
    against the same containment rule - a plugin's skills live inside the workspace, and a
    root that resolves out of it is refused rather than followed - and a name already
    claimed by the repository (or by an earlier root) is an error, never a shadow: which
    instructions the model sees must not depend on discovery order.

    ``reviewed_digests`` pins workspace skill paths to SHA-256 of the exact bytes
    parsed here; absent pins or changed bytes are refused. Plugin extra roots keep
    their separate bundle trust source. This does not pin later tool reads of bodies.
    """
    root = Path(workspace).resolve()
    skills: list[Skill] = list(_scan(root / SKILLS_DIRECTORY, root, reviewed_digests))
    for extra in extra_roots:
        directory = Path(extra).resolve(strict=False)
        if not directory.is_relative_to(root):
            raise SkillError(
                f"skill root {extra} resolves outside the workspace root {root}; a plugin may not "
                "contribute skills from somewhere the run is not confined to"
            )
        claimed = {skill.name for skill in skills}
        for skill in _scan(directory, root, extra_digests, require_pins=extra_digests is not None):
            if skill.name in claimed:
                raise SkillError(
                    f"{skill.name}: two installed skill packages claim the same name "
                    f"({skill.path}); rename or drop one - the model must not be shown one of them "
                    "because of a discovery order nobody chose"
                )
            skills.append(skill)
    return tuple(sorted(skills, key=lambda skill: skill.name))


def _scan(
    directory: Path,
    root: Path,
    reviewed_digests: Mapping[str, str] | None = None,
    *,
    require_pins: bool = False,
) -> list[Skill]:
    """One directory of skill folders, with the symlink refusal the root check requires."""
    if not directory.is_dir():
        return []
    skills: list[Skill] = []
    for entry in sorted(directory.iterdir()):
        if not entry.is_dir():
            continue  # stray files in the skill directory are not skills
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
        expected_digest = None
        if reviewed_digests is not None or require_pins:
            relative = resolved_file.relative_to(root).as_posix()
            expected_digest = (reviewed_digests or {}).get(relative, "")
        skills.append(_parse_skill(resolved_file, expected_digest=expected_digest))
    return skills


def _parse_skill(skill_file: Path, *, expected_digest: str | None = None) -> Skill:
    try:
        raw = skill_file.read_bytes()
    except OSError as error:
        raise SkillError(f"{skill_file}: cannot read skill: {error}") from error
    if expected_digest is not None and hashlib.sha256(raw).hexdigest() != expected_digest:
        raise SkillError(f"{skill_file}: skill changed since review or is unreviewed; refusing metadata")
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
