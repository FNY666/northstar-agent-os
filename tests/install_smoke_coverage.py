"""Install-smoke coverage: does every component's CI packaging smoke check
import every module that component ships?

A packaging smoke step is the check that proves the INSTALLED SURFACE
works:  it installs the wheel, moves to a directory that is not the source
tree, and imports the component's modules.  If a module the component
ships is not reached by that step, the step cannot notice when that module
breaks -- and a broken module in a shipped wheel is exactly the failure a
packaging smoke check exists to catch.

This module holds the DETECTOR, deliberately outside the test file:  the
mutant probe mutates a module and reruns the slice's tests, and a test
file is excluded from the probe by name, so a guard whose logic lives
entirely inside a test file cannot be mutation-probed at all.

A packaging smoke step comes in two shapes.

``IMPORTS``
    ``python -c "import a, b"`` -- the step names its modules.  The
    modules it exercises are the names it imports, plus everything those
    names reach through the component's own import graph.

``SURFACE``
    ``python scripts/check_installed_surface.py <distribution>`` -- the
    step asks the installed distribution which modules it ships and
    imports every one of them.  Such a step covers the whole installed
    surface BY CONSTRUCTION:  it cannot omit a module, because it does
    not name them.

The guard's rule is about what a step COVERS, not about which shape it
has.  A step of either shape is acceptable if it reaches every module the
component ships.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "test.yml"
SURFACE_CHECKER = "check_installed_surface.py"

#: `python -c "..."` and `python3 -c "..."`, with the double-quoted program.
_PYTHON_C = re.compile(r"python(?:3)?\s+-c\s+\"((?:[^\"\\]|\\.)*)\"")
#: `python <path>/check_installed_surface.py <distribution>`.  The path may
#: be quoted and may contain shell variables, so the match is anchored on
#: the script's own name rather than on the path.
_SURFACE = re.compile(
    r"python(?:3)?\s+[\"']?[^\s\"']*%s[\"']?\s+([A-Za-z0-9_.-]+)"
    % re.escape(SURFACE_CHECKER)
)
_WORKING_DIRECTORY = re.compile(r"working-directory:\s*(\S+)")


def imported_names(program: str) -> set[str]:
    """The top-level module names a python program imports.

    ``import a, b`` contributes ``a`` and ``b``.  ``from a import X``
    contributes ``a`` -- ``X`` is an attribute of the module ``a``, not a
    module of its own.  A malformed program contributes nothing rather
    than raising:  the detector must not die on a workflow it cannot
    parse.
    """
    try:
        tree = ast.parse(program)
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


class SmokeStep:
    """One CI packaging smoke step."""

    def __init__(
        self,
        directory: str,
        kind: str,
        roots: frozenset[str],
        distribution: str | None = None,
    ):
        self.directory = directory
        self.kind = kind
        self.roots = roots
        self.distribution = distribution

    @property
    def covers_everything(self) -> bool:
        """True when the step reaches the whole installed surface.

        A surface step does not name its modules, so it cannot omit one.
        """
        return self.kind == "SURFACE"

    def covers_component(self, component: str) -> bool:
        """True when this step covers the given component's whole surface.

        A surface step covers the surface of the distribution it names.
        If it names a DIFFERENT distribution -- a copy-paste error -- it
        checks somebody else's surface, and must not count as covering
        this component's.
        """
        if self.kind != "SURFACE":
            return False
        return self.distribution == component

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "SmokeStep(%r, %r, %r, %r)" % (
            self.directory,
            self.kind,
            sorted(self.roots),
            self.distribution,
        )


def smoke_steps(text: str | None = None) -> list[SmokeStep]:
    """Every CI packaging smoke step in the workflow.

    A job's ``working-directory`` is the directory the job runs in;  the
    last one seen before a command is the one that command runs under.
    A step that runs in a component directory is a step about that
    component.
    """
    source = WORKFLOW.read_text(encoding="utf-8") if text is None else text
    steps: list[SmokeStep] = []
    for match in _PYTHON_C.finditer(source):
        program = match.group(1)
        if "import" not in program:
            continue
        steps.append(
            SmokeStep(
                _directory_at(source, match.start()),
                "IMPORTS",
                frozenset(imported_names(program)),
            )
        )
    for match in _SURFACE.finditer(source):
        steps.append(
            SmokeStep(
                _directory_at(source, match.start()),
                "SURFACE",
                frozenset(),
                match.group(1),
            )
        )
    return steps


def _directory_at(source: str, offset: int) -> str:
    directories = _WORKING_DIRECTORY.findall(source[:offset])
    return directories[-1] if directories else "."


def component_directory(component: str) -> str:
    """The CI working-directory that belongs to a component."""
    return "components/%s" % component


def steps_for(
    component: str, steps: list[SmokeStep] | None = None
) -> list[SmokeStep]:
    """The smoke steps that belong to one component."""
    if steps is None:
        steps = smoke_steps()
    directory = component_directory(component)
    return [step for step in steps if step.directory == directory]


def module_source(component: str, module: str) -> Path | None:
    """The source file of one shipped module.

    A flat module lives at the component root; a package member lives
    inside its package directory.
    """
    root = ROOT / "components" / component
    if "." not in module:
        candidate = root / ("%s.py" % module)
        return candidate if candidate.is_file() else None
    package, _, name = module.partition(".")
    if name == "__init__":
        candidate = root / package / "__init__.py"
    else:
        candidate = root / package / ("%s.py" % name)
    return candidate if candidate.is_file() else None


def import_graph(component: str, shipped: set[str]) -> dict[str, set[str]]:
    """The import graph of the INSTALLED surface.

    The graph is built only over the modules the component SHIPS, from
    their own source.  A test file is deliberately not an edge:  the
    packaging smoke step runs against the installed wheel, where the test
    files do not exist, so a module reachable only from a test file is
    NOT exercised by the step.

    Only IMPORTS THAT RUN AT MODULE IMPORT TIME count.  An import inside
    a function body runs when the function is called, not when the module
    is imported, so the step does not exercise it.
    """
    graph: dict[str, set[str]] = {}
    flat = {name for name in shipped if "." not in name}
    packages = {name.split(".")[0] for name in shipped if "." in name}
    for module in sorted(shipped):
        path = module_source(component, module)
        if path is None:
            graph.setdefault(module, set())
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            graph.setdefault(module, set())
            continue
        dependencies = _import_time_dependencies(tree)
        resolved: set[str] = set()
        for dependency in dependencies:
            if dependency in shipped:
                resolved.add(dependency)
                continue
            root_name = dependency.split(".")[0]
            if root_name in packages:
                # A package reached by name is exercised by importing it.
                resolved.add(root_name)
            elif root_name in flat:
                resolved.add(root_name)
        graph[module] = resolved
    return graph


def _import_time_dependencies(tree: ast.AST) -> set[str]:
    """The modules a module imports when it is imported.

    Function and method bodies are skipped -- their imports run when the
    function is called.  Class bodies and module-level conditionals are
    included:  they run at import time.
    """
    dependencies: set[str] = set()

    def visit(body: list) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level != 0 or not node.module:
                    continue
                dependencies.add(node.module)
                for alias in node.names:
                    dependencies.add("%s.%s" % (node.module, alias.name))
            elif isinstance(node, ast.ClassDef):
                visit(node.body)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            elif isinstance(node, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
                visit(node.body)
                visit(getattr(node, "orelse", []))
                for handler in getattr(node, "handlers", []):
                    visit(handler.body)

    visit(tree.body)
    return dependencies


def reachable(
    roots: set[str], graph: dict[str, set[str]], shipped: set[str]
) -> set[str]:
    """Every shipped module the roots reach, directly or transitively."""
    seen: set[str] = set()
    stack = [root for root in roots if root in shipped]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dependency in graph.get(current, ()):
            if dependency in shipped and dependency not in seen:
                stack.append(dependency)
        # A package reached by name is exercised by importing the package.
        if "." not in current:
            for member in shipped:
                if member.startswith(current + ".") and member not in seen:
                    stack.append(member)
    return seen


def covered_modules(
    component: str,
    shipped: set[str],
    steps: list[SmokeStep] | None = None,
) -> set[str]:
    """The shipped modules the component's CI smoke steps reach."""
    if steps is None:
        steps = smoke_steps()
    component_steps = steps_for(component, steps)
    if any(step.covers_component(component) for step in component_steps):
        return set(shipped)
    roots: set[str] = set()
    for step in component_steps:
        roots |= set(step.roots)
    graph = import_graph(component, shipped)
    return reachable(roots, graph, shipped)


def uncovered_modules(
    component: str,
    shipped: set[str],
    steps: list[SmokeStep] | None = None,
) -> set[str]:
    """The modules the component ships that its CI smoke step never reaches."""
    return set(shipped) - covered_modules(component, shipped, steps)


def missing_smoke_steps(
    components: list[str], steps: list[SmokeStep] | None = None
) -> list[str]:
    """The wheel-shipping components that have no CI packaging smoke step.

    A component with no smoke step is a component whose installed surface
    is never checked at all, which is worse than one whose step covers
    too little.  The guard must name it rather than treat it as
    vacuously covered.
    """
    if steps is None:
        steps = smoke_steps()
    missing = []
    for component in components:
        if not steps_for(component, steps):
            missing.append(component)
    return missing
