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

SCHEMA = "northstar.runtime-module-inventory.v2"
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


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return ".".join(part for part in (prefix, node.attr) if part)
    return ""


def _resolve_import_module_name(
    name: str,
    call: ast.Call,
    module: str,
    path: Path,
) -> str | None:
    """Resolve literal ``import_module('.x', package=...)`` names conservatively."""
    if not name.startswith("."):
        return name
    package_node = call.args[1] if len(call.args) > 1 else next(
        (keyword.value for keyword in call.keywords if keyword.arg == "package"),
        None,
    )
    if isinstance(package_node, ast.Constant) and isinstance(package_node.value, str):
        package = package_node.value
    elif isinstance(package_node, ast.Name) and package_node.id == "__package__":
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    else:
        return None
    package_parts = package.split(".") if package else []
    level = len(name) - len(name.lstrip("."))
    if level > len(package_parts):
        return None
    base = package_parts[: len(package_parts) - level + 1]
    suffix = name[level:].split(".") if name[level:] else []
    return ".".join(part for part in (*base, *suffix) if part)


def imports_for(
    module: str,
    path: Path,
    modules: dict[str, Path],
) -> tuple[set[str], list[dict[str, object]], str | None, str | None]:
    try:
        source_bytes = path.read_bytes()
    except OSError as error:
        return set(), [], f"{type(error).__name__}: {error}", None
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    try:
        source = source_bytes.decode("utf-8")
        tree = ast.parse(source, filename=str(path))
    except (UnicodeDecodeError, SyntaxError) as error:
        return set(), [], f"{type(error).__name__}: {error}", source_sha256
    edges: set[str] = set()
    dynamic: list[dict[str, object]] = []

    # Resolve the common import aliases before walking calls. A call such as
    # ``from importlib import import_module as load; load("plugin")`` is just
    # as real an edge as ``importlib.import_module("plugin")``. Treating it as
    # invisible undercounts the production closure and can misclassify a module
    # as unused. This remains deliberately static: computed names are reported
    # as dynamic sites but are not guessed into the import graph.
    importlib_names = {"importlib"}
    importlib_util_names = {"importlib.util"}
    import_module_names = {"import_module"}
    import_function_names = {"__import__"}
    spec_loader_names = {"spec_from_file_location"}
    builtins_names = {"builtins"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or "importlib")
                elif alias.name == "importlib.util":
                    importlib_util_names.add(alias.asname or "importlib.util")
                elif alias.name == "builtins":
                    builtins_names.add(alias.asname or "builtins")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "importlib":
                import_module_names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "import_module"
                )
                importlib_util_names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "util"
                )
            elif node.module == "importlib.util":
                spec_loader_names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "spec_from_file_location"
                )
            elif node.module == "builtins":
                import_function_names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "__import__"
                )

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
            function_name = _dotted_name(node.func)
            if function_name in import_function_names:
                called = "__import__"
            elif function_name in import_module_names:
                called = "importlib.import_module"
            elif function_name in spec_loader_names:
                called = "importlib.util.spec_from_file_location"
            elif any(
                function_name == f"{prefix}.import_module"
                for prefix in importlib_names
            ):
                called = "importlib.import_module"
            elif any(
                function_name == f"{prefix}.spec_from_file_location"
                for prefix in importlib_util_names
            ):
                called = "importlib.util.spec_from_file_location"
            elif any(
                function_name == f"{prefix}.__import__"
                for prefix in builtins_names
            ):
                called = "__import__"
            if called:
                literal_node = node.args[0] if node.args else next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "name"),
                    None,
                )
                literal = (
                    literal_node.value
                    if isinstance(literal_node, ast.Constant)
                    and isinstance(literal_node.value, str)
                    else None
                )
                dynamic.append({"line": node.lineno, "call": called, "literal": literal})
                if literal:
                    import_name = (
                        _resolve_import_module_name(literal, node, module, path)
                        if called == "importlib.import_module"
                        else literal
                    )
                    if import_name:
                        names.append(import_name)
        for name in names:
            found = _candidate(name, modules)
            if found and found != module:
                edges.add(found)
    return edges, dynamic, None, source_sha256


def inventory(runtime: Path, roots: Iterable[str]) -> dict[str, object]:
    modules = discover(runtime)
    graph: dict[str, set[str]] = {}
    dynamic: dict[str, list[dict[str, object]]] = {}
    source_hashes: dict[str, str | None] = {}
    parse_errors: dict[str, str] = {}
    for name, path in modules.items():
        edges, calls, error, source_sha256 = imports_for(name, path, modules)
        graph[name] = edges
        source_hashes[name] = source_sha256
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
            "source_sha256": source_hashes[name],
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
