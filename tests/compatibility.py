"""Cross-component compatibility matrix and clean-tree contract checks.

This deliberately checks only static contracts: package metadata, console
entry points, and the cross-runtime app-server schema. It never imports a
component or makes a network request, so CI can run it before installation.
"""
from __future__ import annotations

import re
from pathlib import Path

try:  # Python 3.11+; the fallback keeps this pre-install gate Python 3.10-safe.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised only on Python 3.10
    tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
PACKAGED_COMPONENTS = (
    "northstar-run-contract",
    "northstar-host",
    "northstar-durable-run",
    "northstar-agent-interop",
    "northstar-agent-runtime",
)
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:\.dev\d+)?$")


def _project(component: str) -> dict:
    path = ROOT / "components" / component / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    if tomllib is not None:
        return tomllib.loads(text)["project"]

    # Only the [project] fields and [project.scripts] table are needed here.
    # Keep the fallback deliberately small and dependency-free: this checker is
    # an installation preflight, so it must not require tomli in a fresh 3.10
    # virtualenv just to inspect these repository-owned metadata files.
    project_match = re.search(r"(?ms)^\[project\]\s*\n(?P<body>.*?)(?=^\[|\Z)", text)
    scripts_match = re.search(r"(?ms)^\[project\.scripts\]\s*\n(?P<body>.*?)(?=^\[|\Z)", text)
    project_body = project_match.group("body") if project_match else ""
    scripts_body = scripts_match.group("body") if scripts_match else ""

    def string_field(body: str, field: str) -> str | None:
        match = re.search(rf"(?m)^\s*{re.escape(field)}\s*=\s*[\x22']([^\x22']*)[\x22']", body)
        return match.group(1) if match else None

    scripts = {
        match.group(1): match.group(2)
        for match in re.finditer(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*=\s*[\x22']([^\x22']*)[\x22']", scripts_body)
    }
    return {"name": string_field(project_body, "name"), "version": string_field(project_body, "version"), "scripts": scripts}


def _constant(path: Path, name: str, *, exported: bool = False) -> str | None:
    declaration = rf"export\s+const\s+{name}" if exported else rf"{name}"
    match = re.search(rf"(?m)^\s*{declaration}\s*=\s*[\x22']([^\x22']+)[\x22']", path.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def compatibility_errors() -> list[str]:
    errors: list[str] = []
    projects = {name: _project(name) for name in PACKAGED_COMPONENTS}
    versions = {name: project.get("version") for name, project in projects.items()}
    if any(not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version) for version in versions.values()):
        errors.append(f"malformed component version(s): {versions}")
    if len(set(versions.values())) != 1:
        errors.append(f"component versions drifted: {versions}")
    for component, project in projects.items():
        if project.get("name") != component:
            errors.append(f"{component} metadata name is {project.get('name')!r}")

    scripts: dict[str, tuple[str, str]] = {}
    for component, project in projects.items():
        for script, target in project.get("scripts", {}).items():
            previous = scripts.get(script)
            if previous is not None:
                errors.append(f"console entry point {script!r} is declared by both {previous[0]} and {component}")
            else:
                scripts[script] = (component, target)

    expected_scripts = {
        "northstar-agent-runtime": ("northstar-agent-runtime", "cli:main"),
        "northstar-durable-run": ("northstar-durable-run", "durable_cli:main"),
    }
    for component, (script, target) in expected_scripts.items():
        actual = projects[component].get("scripts", {}).get(script)
        if actual != target:
            errors.append(f"{component} entry point {script!r} is {actual!r}, expected {target!r}")

    app_server = ROOT / "components" / "northstar-agent-runtime" / "app_server.py"
    node_client = ROOT / "examples" / "app-server" / "node_client.mjs"
    protocol = _constant(app_server, "APP_PROTOCOL")
    capability_schema = _constant(app_server, "APP_CAPABILITY_SCHEMA")
    node_protocol = _constant(node_client, "APP_PROTOCOL", exported=True)
    node_schema = _constant(node_client, "APP_CAPABILITY_SCHEMA", exported=True)
    if not protocol or not capability_schema:
        errors.append("Python app-server protocol constants are missing")
    if not node_protocol or not node_schema:
        errors.append("Node app-server protocol constants are missing")
    if protocol != node_protocol:
        errors.append(f"Python/Node app protocol drifted: {protocol!r} != {node_protocol!r}")
    if capability_schema != node_schema:
        errors.append(f"Python/Node capability schema drifted: {capability_schema!r} != {node_schema!r}")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    install_match = re.search(r"(?ms)^install[^\n]*\n(?P<body>.*?)(?=^\S|\Z)", makefile)
    install_body = install_match.group("body") if install_match else ""
    if "compatibility" not in (install_match.group(0) if install_match else ""):
        errors.append("Makefile install target does not run the pre-install compatibility gate")
    for component in PACKAGED_COMPONENTS:
        command = f"./.venv/bin/pip install ./components/{component}"
        if command not in install_body:
            errors.append(f"Makefile install target omits {component}")
    api_page = (ROOT / "docs" / "api" / "northstar-durable-run.md").read_text(encoding="utf-8")
    if "components/northstar-durable-run/durable_cli.py" not in api_page:
        errors.append("durable-run API page is not aligned with durable_cli.py")
    if "components/northstar-durable-run/cli.py" in api_page:
        errors.append("durable-run API page still references the colliding cli.py")
    return errors


def main() -> int:
    errors = compatibility_errors()
    if errors:
        for error in errors:
            print(f"[compatibility] ERROR: {error}")
        return 1
    versions = {name: _project(name)["version"] for name in PACKAGED_COMPONENTS}
    print(f"compatibility matrix OK: {len(PACKAGED_COMPONENTS)} components at {next(iter(versions.values()))}")
    print("app-server Python/Node protocol and capability schema: aligned")
    print("console entry points: runtime cli:main; durable-run durable_cli:main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
