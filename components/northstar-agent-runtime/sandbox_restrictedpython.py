"""RestrictedPython AST whitelist (config/policy layer only), Simulated.

Validates Python source against an AST node whitelist and a builtins
allowlist.  Rejects dangerous constructs (import of blocked modules,
eval/exec, dunder access, etc.) before execution.

Does NOT execute code.  Static validation only.

What this IS: pre-execution static gate for Python snippets.

What this IS NOT:
* Not a full sandbox -- must be combined with an execution sandbox.
* AST checks cannot catch all dynamic tricks; defense in depth.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Set

#: Module version.
RESTRICTED_PYTHON_VERSION = "sandbox-restricted-python.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-restricted-python.v1"


class RestrictedPythonError(Exception):
    """Fail-closed: rejected code raises."""


# AST nodes that are always allowed.
ALLOWED_NODES = frozenset({
    "Module", "Expr", "Assign", "AnnAssign", "AugAssign",
    "Name", "Constant", "BinOp", "UnaryOp", "BoolOp", "Compare",
    "If", "IfExp", "For", "While", "Break", "Continue", "Pass",
    "Return", "FunctionDef", "Lambda", "Call", "Attribute",
    "Subscript", "List", "Tuple", "Dict", "Set", "ListComp",
    "SetComp", "DictComp", "GeneratorExp",
    "Add", "Sub", "Mult", "Div", "FloorDiv", "Mod", "Pow",
    "Eq", "NotEq", "Lt", "LtE", "Gt", "GtE", "And", "Or", "Not",
    "USub", "UAdd", "Invert",
    "Load", "Store", "Del",
    "arguments", "arg", "keyword",
    "Slice", "Index",
    "Import", "ImportFrom", "alias",
    "comprehension",
})

# Builtins allowlist.
ALLOWED_BUILTINS = frozenset({
    "abs", "all", "any", "bool", "dict", "enumerate", "float",
    "int", "len", "list", "max", "min", "print", "range",
    "repr", "round", "set", "sorted", "str", "sum", "tuple",
    "zip", "isinstance", "ord", "chr",
})

# Modules that may be imported.
ALLOWED_IMPORTS = frozenset({
    "math", "json", "re", "datetime", "collections", "itertools",
    "functools", "string", "decimal", "fractions",
})

# Names that are never allowed (even if node type is fine).
BLOCKED_NAMES = frozenset({
    "eval", "exec", "compile", "__import__", "open",
    "globals", "locals", "vars", "dir", "getattr", "setattr",
    "delattr", "hasattr", "input", "__builtins__",
})


def check_source(source: str) -> Dict[str, Any]:
    """Validate Python source.  Returns summary.

    Raises RestrictedPythonError on any violation.
    """
    if not isinstance(source, str) or not source.strip():
        raise RestrictedPythonError("source required")
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise RestrictedPythonError(f"syntax error: {e}")
    violations: List[str] = []
    for node in ast.walk(tree):
        node_type = type(node).__name__
        if node_type not in ALLOWED_NODES:
            violations.append(f"blocked node: {node_type}")
        if isinstance(node, ast.Name) and node.id in BLOCKED_NAMES:
            violations.append(f"blocked name: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            violations.append(f"dunder attribute: {node.attr}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in ALLOWED_IMPORTS:
                    violations.append(f"blocked import: {alias.name}")
            if isinstance(node, ast.ImportFrom) and node.level and node.level > 0:
                violations.append("relative import blocked")
    if violations:
        raise RestrictedPythonError("; ".join(violations[:5]))
    return {"nodes": len(list(ast.walk(tree))), "status": "allowed"}


def safe_builtins() -> Dict[str, Any]:
    """Return a restricted __builtins__ dict for exec()."""
    import builtins
    return {name: getattr(builtins, name) for name in ALLOWED_BUILTINS
            if hasattr(builtins, name)}


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "builtins", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert check_source("x = [i * 2 for i in range(10)]")["status"] == "allowed"
    assert check_source("import math\nprint(math.pi)")["status"] == "allowed"
    for bad in [
        "eval('1+1')",
        "import os",
        "open('/etc/passwd')",
        "x.__class__",
        "while True: pass\nimport sys",
    ]:
        try:
            check_source(bad)
            raise AssertionError(f"should raise for {bad!r}")
        except RestrictedPythonError:
            pass
    assert "eval" not in safe_builtins()
    assert "len" in safe_builtins()
    assert stdlib_only()
    print("sandbox-restricted-python OK")


if __name__ == "__main__":
    main()
