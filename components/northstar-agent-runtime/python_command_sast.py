"""Bounded AST taint analysis for Python shell command injection.

The analyzer tracks simple values from common request, CLI, environment, and
interactive input sources to shell-backed process APIs. It handles multiline
calls, assignments, f-strings, imports, basic control-flow joins, and bounded
calls to direct same-file helper functions. It remains a heuristic: it does not
resolve cross-file, method-dispatch, or dynamic-alias flows, custom sanitizers,
or whether non-shell subprocess arguments are semantically dangerous.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


RULE_ID = "PY013_COMMAND_INJECTION"
SEVERITY = "high"
MESSAGE = "untrusted value reaches a shell command"
REMEDIATION = (
    "Avoid shell execution; pass a fixed executable and argument list with shell=False, "
    "and validate each argument against an allowlist."
)
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_AST_NODES = 50_000
_MAX_HELPER_DEPTH = 6
_SUBPROCESS_SINKS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
}
_DIRECT_SHELL_SINKS = {
    "os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell",
}
_REQUEST_FIELDS = {
    "args", "form", "values", "cookies", "headers", "files", "GET", "POST",
    "query_params", "path_params", "json", "data", "url", "path", "path_info",
}


@dataclass(frozen=True)
class _Taint:
    source_line: int


@dataclass(frozen=True)
class _Finding:
    line: int
    column: int
    source_line: int
    sink: str


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


class _Analyzer:
    def __init__(self, tree: ast.Module) -> None:
        self.findings: list[_Finding] = []
        self.module_aliases: dict[str, str] = {}
        self.imported_names: dict[str, str] = {}
        # The first interprocedural increment is deliberately narrow: direct
        # calls to top-level functions in this file. A source scan is already
        # capped at _MAX_AST_NODES; helper visits share the same additional
        # work budget and recursion is bounded to keep hostile source cheap.
        self._local_functions = {
            statement.name: statement
            for statement in tree.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self._function_cost = {
            name: sum(1 for _ in ast.walk(function))
            for name, function in self._local_functions.items()
        }
        self._helper_work_remaining = _MAX_AST_NODES
        self._helper_stack: list[str] = []
        self._return_frames: list[list[_Taint]] = []
        self._local_call_cache: dict[
            tuple[int, tuple[tuple[str, int], ...]], tuple[bool, _Taint | None]
        ] = {}
        self._statements(tree.body, {})

    def _canonical_name(self, node: ast.AST) -> str | None:
        name = _dotted_name(node)
        if not name:
            return None
        head, dot, tail = name.partition(".")
        replacement = self.imported_names.get(head, self.module_aliases.get(head, head))
        return replacement + (dot + tail if dot else "")

    @staticmethod
    def _is_request_source(name: str) -> bool:
        parts = name.split(".")
        if len(parts) < 2:
            return False
        field = parts[-1]
        prefix = ".".join(parts[:-1])
        return (
            field in _REQUEST_FIELDS
            and (prefix in {"request", "flask.request"}
                 or prefix.endswith(".request"))
        )

    def _source_line(self, node: ast.AST) -> int | None:
        if isinstance(node, ast.Call):
            name = self._canonical_name(node.func)
            if name in {"input", "builtins.input", "getpass.getpass", "os.getenv"}:
                return getattr(node, "lineno", 1)
        name = self._canonical_name(node)
        if name in {"sys.argv", "os.environ"}:
            return getattr(node, "lineno", 1)
        if name and self._is_request_source(name):
            return getattr(node, "lineno", 1)
        return None

    def _taint(self, node: ast.AST | None, env: dict[str, _Taint]) -> _Taint | None:
        if node is None:
            return None
        source_line = self._source_line(node)
        if source_line is not None:
            return _Taint(source_line)
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.Call):
            name = self._canonical_name(node.func)
            if name in _SUBPROCESS_SINKS | _DIRECT_SHELL_SINKS:
                # A process API's result is not the command string it consumed.
                return None
            if self._function_name(node) in self._local_functions:
                analyzed, helper_result = self._local_call_result(node, env)
                if analyzed:
                    return helper_result
        origins = [self._taint(child, env) for child in ast.iter_child_nodes(node)]
        tainted = [origin for origin in origins if origin is not None]
        return min(tainted, key=lambda origin: origin.source_line) if tainted else None

    @staticmethod
    def _function_name(call: ast.Call) -> str | None:
        # Attribute calls are intentionally excluded: resolving self.foo or
        # module.foo safely needs class/module identity and dispatch analysis.
        return call.func.id if isinstance(call.func, ast.Name) else None

    def _local_call_environment(
        self,
        call: ast.Call,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        caller_env: dict[str, _Taint],
    ) -> dict[str, _Taint]:
        positional = [*function.args.posonlyargs, *function.args.args]
        keyword_only = list(function.args.kwonlyargs)
        parameters = [*positional, *keyword_only]
        values: dict[str, ast.AST] = {}
        starred_origins: list[_Taint] = []
        for index, parameter in enumerate(positional):
            if index < len(call.args):
                argument = call.args[index]
                if isinstance(argument, ast.Starred):
                    values[parameter.arg] = argument.value
                    origin = self._taint(argument.value, caller_env)
                    if origin is not None:
                        starred_origins.append(origin)
                else:
                    values[parameter.arg] = argument
        for keyword in call.keywords:
            if keyword.arg is not None:
                values[keyword.arg] = keyword.value

        environment: dict[str, _Taint] = {}
        for parameter in parameters:
            argument = values.get(parameter.arg)
            if argument is not None:
                taint = self._taint(argument, caller_env)
                if taint is not None:
                    environment[parameter.arg] = taint

        # A starred tuple can fill any remaining positional slot. Preserve the
        # flow conservatively rather than assuming the first slot is the only
        # destination when the number of expanded values is unknown.
        if starred_origins:
            star_origin = min(starred_origins, key=lambda item: item.source_line)
            for parameter in positional:
                previous = environment.get(parameter.arg)
                if previous is None or star_origin.source_line < previous.source_line:
                    environment[parameter.arg] = star_origin

        if function.args.vararg is not None:
            extras = call.args[len(positional):]
            tainted = [self._taint(item.value if isinstance(item, ast.Starred) else item, caller_env)
                       for item in extras]
            origins = [item for item in tainted if item is not None]
            origins.extend(starred_origins)
            if origins:
                environment[function.args.vararg.arg] = min(origins, key=lambda item: item.source_line)
        if function.args.kwarg is not None:
            extras = [keyword.value for keyword in call.keywords if keyword.arg is None]
            origins = [self._taint(item, caller_env) for item in extras]
            origins = [item for item in origins if item is not None]
            if origins:
                origin = min(origins, key=lambda item: item.source_line)
                environment[function.args.kwarg.arg] = origin
                # Unknown keyword names may bind any declared parameter.
                for parameter in parameters:
                    previous = environment.get(parameter.arg)
                    if previous is None or origin.source_line < previous.source_line:
                        environment[parameter.arg] = origin
        return environment

    def _local_call_result(
        self, call: ast.Call, caller_env: dict[str, _Taint]
    ) -> tuple[bool, _Taint | None]:
        name = self._function_name(call)
        function = self._local_functions.get(name or "")
        if (
            function is None
            or name in self._helper_stack
            or len(self._helper_stack) >= _MAX_HELPER_DEPTH
        ):
            return False, None

        function_env = self._local_call_environment(call, function, caller_env)
        cache_key = (id(call), tuple(sorted(
            (parameter, taint.source_line) for parameter, taint in function_env.items()
        )))
        if cache_key in self._local_call_cache:
            return self._local_call_cache[cache_key]

        cost = self._function_cost.get(name, _MAX_AST_NODES + 1)
        if cost > self._helper_work_remaining:
            return False, None
        self._helper_work_remaining -= cost
        self._helper_stack.append(name)
        returns: list[_Taint] = []
        self._return_frames.append(returns)
        try:
            self._scoped(function.body, function_env)
        except RecursionError:
            # Deeply nested hostile ASTs are ignored at this helper boundary.
            result = None
        else:
            result = min(returns, key=lambda item: item.source_line) if returns else None
        finally:
            self._return_frames.pop()
            self._helper_stack.pop()
        analyzed_result = (True, result)
        self._local_call_cache[cache_key] = analyzed_result
        return analyzed_result

    @staticmethod
    def _target_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for child in target.elts for name in _Analyzer._target_names(child)]
        return []

    def _assign(self, target: ast.AST, value: ast.AST | None, env: dict[str, _Taint]) -> None:
        taint = self._taint(value, env)
        for name in self._target_names(target):
            if taint is None:
                env.pop(name, None)
            else:
                env[name] = taint

    def _call_sink(self, call: ast.Call, env: dict[str, _Taint]) -> None:
        name = self._canonical_name(call.func)
        if not name:
            return
        shell_enabled = False
        if name in _SUBPROCESS_SINKS:
            shell_argument = next((
                keyword.value for keyword in call.keywords if keyword.arg == "shell"
            ), None)
            if shell_argument is None and name == "subprocess.Popen" and len(call.args) > 8:
                shell_argument = call.args[8]
            if shell_argument is None:
                shell_enabled = any(keyword.arg is None for keyword in call.keywords)
            else:
                shell_enabled = (
                    not isinstance(shell_argument, ast.Constant)
                    or bool(shell_argument.value)
                )
        elif name in _DIRECT_SHELL_SINKS:
            shell_enabled = True
        if not shell_enabled:
            return

        command: ast.AST | None = None
        if name in _SUBPROCESS_SINKS:
            command = next((kw.value for kw in call.keywords if kw.arg in {"args", "command"}), None)
            if command is None and call.args:
                command = call.args[0]
        else:
            command = next((kw.value for kw in call.keywords if kw.arg in {"command", "cmd"}), None)
            if command is None and call.args:
                command = call.args[0]
        origin = self._taint(command, env)
        if origin is not None:
            self.findings.append(_Finding(
                line=getattr(call, "lineno", 1),
                column=getattr(call, "col_offset", 0) + 1,
                source_line=origin.source_line,
                sink=name,
            ))

    def _expression(self, node: ast.AST | None, env: dict[str, _Taint]) -> None:
        if node is None:
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._call_sink(child, env)
                name = self._function_name(child)
                if name in self._local_functions:
                    function = self._local_functions[name]
                    if self._local_call_environment(child, function, env):
                        self._local_call_result(child, env)

    @staticmethod
    def _merge(*environments: dict[str, _Taint]) -> dict[str, _Taint]:
        merged: dict[str, _Taint] = {}
        for env in environments:
            for name, taint in env.items():
                previous = merged.get(name)
                if previous is None or taint.source_line < previous.source_line:
                    merged[name] = taint
        return merged

    def _scoped(self, statements: list[ast.stmt], env: dict[str, _Taint]) -> None:
        saved_modules = self.module_aliases
        saved_imports = self.imported_names
        self.module_aliases = dict(saved_modules)
        self.imported_names = dict(saved_imports)
        self._statements(statements, dict(env))
        self.module_aliases = saved_modules
        self.imported_names = saved_imports

    def _statements(self, statements: list[ast.stmt], env: dict[str, _Taint]) -> dict[str, _Taint]:
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    self.module_aliases[local] = alias.name
            elif isinstance(statement, ast.ImportFrom):
                module = statement.module or ""
                for alias in statement.names:
                    if alias.name == "*":
                        continue
                    self.imported_names[alias.asname or alias.name] = f"{module}.{alias.name}".strip(".")
            elif isinstance(statement, ast.Assign):
                self._expression(statement.value, env)
                for target in statement.targets:
                    self._assign(target, statement.value, env)
            elif isinstance(statement, ast.AnnAssign):
                self._expression(statement.value, env)
                self._assign(statement.target, statement.value, env)
            elif isinstance(statement, ast.AugAssign):
                self._expression(statement.value, env)
                origin = self._taint(statement.target, env) or self._taint(statement.value, env)
                for name in self._target_names(statement.target):
                    if origin is None:
                        env.pop(name, None)
                    else:
                        env[name] = origin
            elif isinstance(statement, ast.Expr):
                self._expression(statement.value, env)
            elif isinstance(statement, (ast.Return, ast.Raise, ast.Assert)):
                value = getattr(statement, "value", None)
                if isinstance(statement, ast.Return) and self._return_frames:
                    origin = self._taint(value, env)
                    if origin is not None:
                        self._return_frames[-1].append(origin)
                self._expression(value, env)
                self._expression(getattr(statement, "test", None), env)
                self._expression(getattr(statement, "exc", None), env)
            elif isinstance(statement, ast.If):
                self._expression(statement.test, env)
                left, right = dict(env), dict(env)
                self._statements(statement.body, left)
                self._statements(statement.orelse, right)
                env.clear()
                env.update(self._merge(left, right))
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                self._expression(statement.iter, env)
                body_env, else_env = dict(env), dict(env)
                self._assign(statement.target, statement.iter, body_env)
                self._statements(statement.body, body_env)
                self._statements(statement.orelse, else_env)
                env.clear()
                env.update(self._merge(body_env, else_env))
            elif isinstance(statement, ast.While):
                self._expression(statement.test, env)
                body_env, else_env = dict(env), dict(env)
                self._statements(statement.body, body_env)
                self._statements(statement.orelse, else_env)
                env.clear()
                env.update(self._merge(body_env, else_env))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                body_env = dict(env)
                for item in statement.items:
                    self._expression(item.context_expr, body_env)
                    if item.optional_vars is not None:
                        self._assign(item.optional_vars, item.context_expr, body_env)
                self._statements(statement.body, body_env)
                env.clear()
                env.update(body_env)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in statement.decorator_list:
                    self._expression(decorator, env)
                for default in (*statement.args.defaults, *statement.args.kw_defaults):
                    self._expression(default, env)
                # A nested function's return is not a return from its enclosing
                # helper. Keep its direct sink scan, but isolate the summary
                # frame so an uncalled nested function cannot taint a caller's
                # return value.
                self._return_frames.append([])
                try:
                    self._scoped(statement.body, env)
                finally:
                    self._return_frames.pop()
            elif isinstance(statement, ast.ClassDef):
                for expression in (*statement.bases, *statement.decorator_list):
                    self._expression(expression, env)
                self._scoped(statement.body, env)
            elif isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                branch_envs: list[dict[str, _Taint]] = []
                body_env = dict(env)
                self._statements(statement.body, body_env)
                self._statements(statement.orelse, body_env)
                branch_envs.append(body_env)
                for handler in statement.handlers:
                    handler_env = dict(env)
                    self._expression(handler.type, handler_env)
                    self._statements(handler.body, handler_env)
                    branch_envs.append(handler_env)
                env.clear()
                env.update(self._merge(*branch_envs))
                self._statements(statement.finalbody, env)
            elif isinstance(statement, (ast.Match,)):
                self._expression(statement.subject, env)
                branches = []
                for case in statement.cases:
                    case_env = dict(env)
                    self._expression(case.guard, case_env)
                    self._statements(case.body, case_env)
                    branches.append(case_env)
                env.clear()
                env.update(self._merge(*branches, env))
            else:
                self._expression(statement, env)
        return env


def scan_source(source: Any) -> list[dict[str, Any]]:
    """Return request/CLI/environment-to-shell command flow findings."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the 1 MiB scan limit")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return []

    for node_count, _ in enumerate(ast.walk(tree), start=1):
        if node_count > _MAX_AST_NODES:
            return []

    try:
        analyzer = _Analyzer(tree)
    except RecursionError:
        return []
    unique = {
        (finding.line, finding.column, finding.source_line, finding.sink): finding
        for finding in analyzer.findings
    }
    return [
        {
            "rule": RULE_ID,
            "severity": SEVERITY,
            "message": (
                f"untrusted value from line {finding.source_line} reaches shell command "
                f"execution via {finding.sink}"
            ),
            "remediation": REMEDIATION,
            "line": finding.line,
            "column": finding.column,
        }
        for finding in sorted(unique.values(), key=lambda item: (item.line, item.column, item.sink))
    ]


__all__ = ["MESSAGE", "REMEDIATION", "RULE_ID", "SEVERITY", "scan_source"]
