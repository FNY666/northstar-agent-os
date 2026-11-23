"""Shared local and CI checks for a Northstar software release."""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

PACKAGED = (
    "northstar-run-contract",
    "northstar-host",
    "northstar-durable-run",
    "northstar-agent-interop",
    "northstar-agent-runtime",
)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:\.dev\d+)?$")
DEV_RE = re.compile(r"\.dev\d+$")


def component_version(root: Path, name: str) -> str:
    """Read a component's declared project version."""
    path = root / "components" / name / "pyproject.toml"
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    return document["project"]["version"]


def runtime_module_version(root: Path) -> str:
    """Read the version printed by the runtime CLI."""
    path = root / "components" / "northstar-agent-runtime" / "_version.py"
    text = path.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
    if not match:
        raise ValueError(f"could not parse __version__ from {path}")
    return match.group(1)


def versions_for(root: Path) -> tuple[dict[str, str], str]:
    """Return declared component versions and the runtime module version."""
    versions = {name: component_version(root, name) for name in PACKAGED}
    return versions, runtime_module_version(root)


def validate_versions(
    versions: dict[str, str],
    runtime_version: str,
    *,
    tag: str | None = None,
    require_development: bool = False,
) -> list[str]:
    """Return human-readable release readiness failures."""
    errors: list[str] = []
    for name, version in versions.items():
        if not VERSION_RE.fullmatch(version):
            errors.append(f"{name} has malformed version {version!r}")
    if not VERSION_RE.fullmatch(runtime_version):
        errors.append(f"runtime _version.py has malformed version {runtime_version!r}")

    all_versions = set(versions.values())
    if len(all_versions) != 1:
        errors.append(f"component versions drifted: {versions}")
    if versions.get("northstar-agent-runtime") != runtime_version:
        errors.append(
            "runtime _version.py does not match northstar-agent-runtime: "
            f"{runtime_version!r} != {versions.get('northstar-agent-runtime')!r}"
        )

    aligned = next(iter(all_versions), None)
    if require_development and aligned is not None and not DEV_RE.search(aligned):
        errors.append(f"working tree version must be development-suffixed: {aligned!r}")

    if tag is not None:
        if aligned is None:
            errors.append("cannot validate tag while component versions are unavailable")
        else:
            if DEV_RE.search(aligned):
                errors.append(f"tag release cannot use development version {aligned!r}")
            if tag != f"v{aligned}":
                errors.append(f"tag {tag!r} does not match aligned version v{aligned}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="check Northstar release version readiness")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag", help="validate a release tag such as v0.1.0")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    versions, runtime_version = versions_for(root)
    errors = validate_versions(
        versions,
        runtime_version,
        tag=args.tag,
        require_development=args.tag is None,
    )
    print("release versions:")
    for name in PACKAGED:
        print(f"  {name}: {versions[name]}")
    print(f"  runtime _version.py: {runtime_version}")
    if args.tag:
        print(f"  tag: {args.tag}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("release-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
