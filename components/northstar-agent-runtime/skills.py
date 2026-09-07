"""Standards-compatible workspace Agent Skills (progressive disclosure).

Northstar consumes the portable ``SKILL.md`` format as a **read-only knowledge
package**. At startup it exposes only each skill's name and description; the
model can load the body through the ordinary sandboxed ``Read`` tool when a task
matches. A skill file is text, never an execution or permission channel. In
particular, the open standard's ``allowed-tools`` field is metadata here: it
never auto-approves a Northstar tool and all calls still cross the runtime's
permission gate and hooks.

The loader accepts Northstar's historical ``.northstar/skills`` directory and
the portable ``.agents/skills`` directory. A caller can pass explicit
workspace-relative directories for another integration. Every discovered skill
is checked before a run starts: standard name/description bounds, parent
folder identity, supported metadata types, duplicate names, and symlink
containment. ``skills check`` uses the same loader, so validation cannot drift
from what a real run will consume.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from frontmatter import FrontmatterError, parse_frontmatter

SKILLS_DIRECTORY = ".northstar/skills"
PORTABLE_SKILLS_DIRECTORY = ".agents/skills"
DEFAULT_SKILL_DIRECTORIES: tuple[str, ...] = (SKILLS_DIRECTORY, PORTABLE_SKILLS_DIRECTORY)
SKILL_FILE_NAME = "SKILL.md"
MAX_SKILLS = 40
MAX_NAME_CHARS = 64
MAX_DESCRIPTION_CHARS = 1_024
MAX_COMPATIBILITY_CHARS = 500
MAX_LISTING_CHARS = 8_000
_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

# ``model`` is retained as a harmless Northstar extension for existing local
# skills. The other fields are from agentskills.io's SKILL.md specification.
_ALLOWED_KEYS = frozenset({
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
    "model",
})
_LISTING_START = "\n\n== Workspace skills ==\n"
_LISTING_END = "\n== End of workspace skills =="


class SkillError(ValueError):
    """A workspace skill is unusable. Message is operator-facing."""


@dataclass(frozen=True)
class Skill:
    """Validated skill metadata plus the path to its on-demand instructions."""

    name: str
    description: str
    path: Path            # absolute path of SKILL.md inside the workspace
    model: str = ""      # Northstar extension; never an execution permission
    license: str = ""
    compatibility: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    allowed_tools: tuple[str, ...] = ()

    @property
    def root(self) -> Path:
        """The skill package directory containing ``SKILL.md``."""
        return self.path.parent


def skills_directory(workspace: str | Path) -> Path:
    """Return Northstar's historical skill directory."""
    return Path(workspace) / SKILLS_DIRECTORY


def skill_directories(workspace: str | Path, directories: Sequence[str | Path] | None = None) -> tuple[Path, ...]:
    """Resolve default or explicit skill directories within ``workspace``.

    Absolute paths are accepted only when they still resolve below the
    workspace. This keeps ``--skills-dir`` useful for integrations without
    turning it into a path escape hatch.
    """
    root = Path(workspace).resolve()
    requested: Sequence[str | Path] = DEFAULT_SKILL_DIRECTORIES if directories is None else directories
    resolved: list[Path] = []
    seen: set[Path] = set()
    for value in requested:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve(strict=False)
        if not candidate.is_relative_to(root):
            raise SkillError(
                f"skill directory {value} resolves outside the workspace root {root}; refusing to follow it"
            )
        if candidate not in seen:
            seen.add(candidate)
            resolved.append(candidate)
    return tuple(resolved)


def discover_skills(
    workspace: str | Path,
    *,
    directories: Sequence[str | Path] | None = None,
) -> tuple[Skill, ...]:
    """Discover and validate skills under the workspace root.

    Missing skill directories are fine. A present but malformed skill is not:
    validation errors are fail-closed and prevent the run from starting.
    """
    root = Path(workspace).resolve()
    found: list[Skill] = []
    by_name: dict[str, Path] = {}
    for directory in skill_directories(root, directories):
        if not directory.exists():
            continue
        if not directory.is_dir():
            raise SkillError(f"skill directory {directory} exists but is not a directory")
        for entry in sorted(directory.iterdir(), key=lambda item: item.name):
            resolved_entry = entry.resolve(strict=False)
            if entry.is_symlink():
                if not resolved_entry.is_relative_to(root):
                    raise SkillError(
                        f"skill folder {entry} resolves outside the workspace root {root}; refusing to follow the symlink"
                    )
                # Even an in-workspace symlink makes the package identity
                # ambiguous; a checked-in skill should be a real directory.
                raise SkillError(f"skill folder {entry} is a symlink; use a real directory")
            if not entry.is_dir():
                continue  # stray files in a skills root are not skills
            skill_file = entry / SKILL_FILE_NAME
            if not skill_file.exists() and not skill_file.is_symlink():
                continue  # a folder without SKILL.md is not (yet) a skill
            if skill_file.is_symlink():
                resolved_file = skill_file.resolve(strict=False)
                if not resolved_file.is_relative_to(root):
                    raise SkillError(
                        f"skill file {skill_file} resolves outside the workspace root {root}; refusing to follow the symlink"
                    )
                raise SkillError(f"skill file {skill_file} is a symlink; use a real file")
            resolved_file = skill_file.resolve(strict=True)
            if not resolved_file.is_relative_to(root):
                raise SkillError(
                    f"skill file {skill_file} resolves outside the workspace root {root}; refusing to follow the symlink"
                )
            _validate_package_links(entry, root)
            skill = _parse_skill(resolved_file, expected_directory=entry.name)
            previous = by_name.get(skill.name)
            if previous is not None:
                raise SkillError(
                    f"duplicate skill name {skill.name!r}: {previous} and {skill.path}; "
                    "choose one package or rename it"
                )
            by_name[skill.name] = skill.path
            found.append(skill)
            if len(found) > MAX_SKILLS:
                raise SkillError(
                    f"more than {MAX_SKILLS} skills were found; reduce the workspace skill set "
                    "or use --skills-dir to select a smaller set"
                )
    return tuple(sorted(found, key=lambda skill: skill.name))


def _validate_package_links(skill_directory: Path, workspace_root: Path) -> None:
    """Reject resource symlinks that escape the workspace or skill package."""
    package_root = skill_directory.resolve(strict=True)
    for path in skill_directory.rglob("*"):
        if not path.is_symlink():
            continue
        resolved = path.resolve(strict=False)
        if not resolved.is_relative_to(workspace_root):
            raise SkillError(
                f"skill resource {path} resolves outside the workspace root {workspace_root}; "
                "refusing to follow the symlink"
            )
        if not resolved.is_relative_to(package_root):
            raise SkillError(
                f"skill resource {path} resolves outside its skill package {package_root}; "
                "refusing to follow the symlink"
            )


def _parse_skill(skill_file: Path, *, expected_directory: str) -> Skill:
    try:
        raw = skill_file.read_bytes()
    except OSError as error:
        raise SkillError(f"{skill_file}: cannot read skill: {error}") from error
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SkillError(f"{skill_file}: SKILL.md must be valid UTF-8: {error}") from error
    try:
        fields, _body = parse_frontmatter(text)
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
    if not isinstance(name, str) or not name:
        raise SkillError(f"{skill_file}: name is required")
    if len(name) > MAX_NAME_CHARS or not _NAME_RE.fullmatch(name) or "--" in name:
        raise SkillError(
            f"{skill_file}: name must be 1-{MAX_NAME_CHARS} lowercase letters, numbers and single hyphens "
            "with no leading/trailing hyphen"
        )
    if name != expected_directory:
        raise SkillError(
            f"{skill_file}: name {name!r} must match its parent directory {expected_directory!r}"
        )

    description = fields.get("description")
    if not isinstance(description, str) or not description.strip():
        raise SkillError(f"{skill_file}: description is required (this is the trigger text the model sees)")
    description = description.strip()
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise SkillError(f"{skill_file}: description is longer than {MAX_DESCRIPTION_CHARS} characters")

    license_value = _optional_string(fields, "license", skill_file)
    compatibility = _optional_string(fields, "compatibility", skill_file)
    if len(compatibility) > MAX_COMPATIBILITY_CHARS:
        raise SkillError(f"{skill_file}: compatibility is longer than {MAX_COMPATIBILITY_CHARS} characters")

    metadata_raw = fields.get("metadata", {})
    if not isinstance(metadata_raw, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in metadata_raw.items()
    ):
        raise SkillError(f"{skill_file}: metadata must be a map of string keys to string values")
    metadata = dict(metadata_raw)

    allowed_raw = fields.get("allowed-tools", "")
    if not isinstance(allowed_raw, str):
        raise SkillError(f"{skill_file}: allowed-tools must be a space-separated string")
    allowed_tools = tuple(part for part in allowed_raw.split() if part)

    model = fields.get("model", "")
    if not isinstance(model, str):
        raise SkillError(f"{skill_file}: model must be a string")

    return Skill(
        name=name,
        description=description,
        path=skill_file.resolve(),
        model=model,
        license=license_value,
        compatibility=compatibility,
        metadata=metadata,
        allowed_tools=allowed_tools,
    )


def _optional_string(fields: dict[str, Any], key: str, path: Path) -> str:
    value = fields.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SkillError(f"{path}: {key} must be a string")
    return value.strip()


def skill_as_dict(skill: Skill, workspace: str | Path) -> dict[str, Any]:
    """Return a stable JSON-ready metadata record for ``skills list/check``."""
    root = Path(workspace).resolve()
    return {
        "name": skill.name,
        "description": skill.description,
        "path": str(skill.path),
        "relative_path": str(skill.path.relative_to(root)),
        "license": skill.license or None,
        "compatibility": skill.compatibility or None,
        "metadata": dict(sorted(skill.metadata.items())),
        "allowed_tools": list(skill.allowed_tools),
        "model": skill.model or None,
        "resources": sorted(
            str(path.relative_to(skill.root))
            for path in skill.root.rglob("*")
            if path.is_file() and path.name != SKILL_FILE_NAME
        ),
    }


def skill_listing(skills: Iterable[Skill], workspace: str | Path) -> str:
    """Compose the progressive-disclosure section for the system prompt."""
    root = Path(workspace).resolve()
    bullets: list[str] = []
    for skill in skills:
        relative = skill.path.relative_to(root)
        details = ""
        if skill.allowed_tools:
            details = "  (declared tools: " + ", ".join(skill.allowed_tools) + "; runtime policy still applies)"
        bullets.append(f"- {skill.name}: {skill.description}  (Read '{relative}' for full instructions){details}")
    body = "\n".join(bullets)
    if len(body) > MAX_LISTING_CHARS:
        body = body[:MAX_LISTING_CHARS] + "\n[listing truncated]"
    return f"{_LISTING_START}{body}{_LISTING_END}"
