#!/usr/bin/env python3
"""Build a conservative static module inventory for the Core/Labs split.

This command moves nothing. It parses local imports, computes modules reachable
from production roots, records literal dynamic imports, and leaves every other
module in ``review_required``. Static reachability is evidence for review, not
permission to delete or move a module.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import tempfile
from collections import deque
from pathlib import Path
from typing import Iterable

SCHEMA = "northstar.runtime-module-inventory.v1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = (
    "cli",
    "sdk",
    "loop",
    "events",
    "code_task",
    "verification",
    "providers",
    "tools",
)
EXCLUDED_DIRS = frozenset(
    {"build", "dist", "northstar_agent_runtime.egg-info", "tests", "__pycache__", ".pytest_cache"}
)


def discover(runtime: Path) -> dict[str, Path]:
    modules: dict[str, Path] = {}
    for path in sorted(runtime.rglob("*.py")):
        relative = path.relative_to(runtime)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if len(relative.parts) == 1:
            name = path.stem
        else:
            parts = list(relative.with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            if not parts:
                continue
            name = ".".join(parts)
        modules[name] = path
    return modules


def _candidate(name: str, modules: dict[str, Path]) -> str | None:
    current = name
    while current:
        if current in modules:
            return current
        current = current.rpartition(".")[0]
    return None


def _relative_base(module: str, level: int, *, is_package: bool) -> str:
    package = module if is_package else module.rpartition(".")[0]
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - max(0, level - 1))
    return ".".join(parts[:keep])


def imports_for(
    module: str,
    path: Path,
    modules: dict[str, Path],
) -> tuple[set[str], list[dict[str, object]], str | None]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        return set(), [], f"{type(error).__name__}: {error}"
    edges: set[str] = set()
    dynamic: list[dict[str, object]] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = _relative_base(
                    module,
                    node.level,
                    is_package=path.name == "__init__.py",
                )
                base = ".".join(item for item in (parent, base) if item)
            if base:
                names.append(base)
            for alias in node.names:
                if alias.name != "*":
                    names.append(".".join(item for item in (base, alias.name) if item))
        elif isinstance(node, ast.Call):
            called = ""
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                called = "__import__"
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
            ):
                called = "importlib.import_module"
            if called:
                literal = (
                    node.args[0].value
                    if node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    else None
                )
                dynamic.append({"line": node.lineno, "call": called, "literal": literal})
                if literal:
                    names.append(literal)
        for name in names:
            found = _candidate(name, modules)
            if found and found != module:
                edges.add(found)
    return edges, dynamic, None


def inventory(runtime: Path, roots: Iterable[str]) -> dict[str, object]:
    modules = discover(runtime)
    graph: dict[str, set[str]] = {}
    dynamic: dict[str, list[dict[str, object]]] = {}
    parse_errors: dict[str, str] = {}
    for name, path in modules.items():
        edges, calls, error = imports_for(name, path, modules)
        graph[name] = edges
        if calls:
            dynamic[name] = calls
        if error:
            parse_errors[name] = error

    requested_roots = tuple(dict.fromkeys(str(root).strip() for root in roots if str(root).strip()))
    missing_roots = sorted(root for root in requested_roots if root not in modules)
    reachable: set[str] = set()
    present_roots = [root for root in requested_roots if root in modules]
    queue = deque(present_roots)
    predecessor: dict[str, str | None] = {root: None for root in present_roots}
    reached_from: dict[str, str] = {root: root for root in present_roots}
    while queue:
        current = queue.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        for dependency in sorted(graph.get(current, ())):
            if dependency not in predecessor:
                predecessor[dependency] = current
                reached_from[dependency] = reached_from[current]
                queue.append(dependency)

    review = sorted(set(modules) - reachable)
    def import_path(name: str) -> list[str]:
        path = [name]
        while predecessor[path[-1]] is not None:
            path.append(str(predecessor[path[-1]]))
        return list(reversed(path))

    module_rows = {
        name: {
            "path": modules[name].relative_to(runtime).as_posix(),
            "imports": sorted(graph[name]),
            "classification": "core_reachable" if name in reachable else "review_required",
            **(
                {
                    "reachable_from": reached_from[name],
                    "import_path": import_path(name),
                }
                if name in reachable
                else {}
            ),
        }
        for name in sorted(modules)
    }
    try:
        runtime_root = runtime.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        # Keep custom-tree inventories reproducible across checkout locations.
        runtime_root = runtime.name
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "runtime_root": runtime_root,
        "roots": list(requested_roots),
        "missing_roots": missing_roots,
        "summary": {
            "modules": len(modules),
            "core_reachable": len(reachable),
            "review_required": len(review),
            "dynamic_import_sites": sum(len(rows) for rows in dynamic.values()),
            "parse_errors": len(parse_errors),
        },
        "core_reachable": sorted(reachable),
        "review_required": review,
        "literal_and_dynamic_imports": dynamic,
        "parse_errors": parse_errors,
        "modules": module_rows,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["inventory_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def atomic_write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "components" / "northstar-agent-runtime",
    )
    parser.add_argument("--root", action="append", dest="roots", default=[])
    parser.add_argument("--write", type=Path, default=None, metavar="PATH")
    parser.add_argument("--json", action="store_true", help="print the complete inventory")
    args = parser.parse_args()
    runtime = args.runtime.expanduser().resolve()
    if not runtime.is_dir():
        parser.error(f"runtime directory does not exist: {runtime}")
    payload = inventory(runtime, args.roots or DEFAULT_ROOTS)
    if args.write is not None:
        atomic_write(args.write.expanduser().resolve(), payload)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        summary = payload["summary"]
        print(
            f"modules={summary['modules']} core_reachable={summary['core_reachable']} "
            f"review_required={summary['review_required']} "
            f"dynamic_import_sites={summary['dynamic_import_sites']} "
            f"parse_errors={summary['parse_errors']}"
        )
        print(f"inventory_sha256={payload['inventory_sha256']}")
        if args.write is not None:
            print(f"wrote={args.write.expanduser().resolve()}")
    return 1 if payload["missing_roots"] or payload["parse_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
