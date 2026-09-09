"""Repository-declared lifecycle hooks: the governed subset of a "command hook".

Claude Code let a settings file run a shell command at a lifecycle event, and it
works well for teams - policy review happens in a pull request, not in a Python
file. Northstar wants the same reach, but a workspace-declared hook is *code the
agent's environment can influence*, so this module implements the narrow,
fail-closed version of the idea:

- **Veto-capable events only.** A repository file may add a veto, never a power.
  ``PostToolUse``-style "observe and maybe allow" hooks are refused here because
  they are the half that could widen behaviour (``hooks.VETO_EVENTS`` is the set).
- **No shell.** The schema has no ``command`` string and never calls a shell: a
  declared hook is ``script`` (a workspace-relative file) plus an ``interpreter``
  drawn from a fixed allowlist. ``;``, ``|``, ``&&``, backticks, and ``$( )``
  have no way to exist here, so a poisoned config cannot compose a command.
- **Workspace containment, symlink-first.** The script is resolved with the same
  rule the file tools use: it must live inside the workspace root after
  ``realpath``, be an existing regular file, and not be a symlink. A skill or
  config that points outside the run is refused, never followed.
- **Bounded and killed.** Output caps, a bounded timeout, and TERM-then-KILL of the
  whole process group: a hook that hangs or floods cannot outlive its verdict.
- **Nothing is inherited.** The child gets a scrubbed environment (``PATH`` and
  ``LANG`` only) and the workspace as cwd, so model credentials never cross into
  hook code.
- **Off by default.** ``--enable-workspace-hooks`` is required. Cloning a
  repository must not mean executing it.
- **Fail closed.** A timeout, a non-zero exit with no verdict, or unparseable
  output on a veto event is a denial, not a shrug.

The hook protocol is a JSON request on stdin (``HookInput.as_dict()``) and an
optional JSON verdict on stdout, coerced by :func:`hooks.coerce_result` - the same
vocabulary an in-process Python hook returns, so one hook can be promoted from a
script to a callback without changing meaning.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from hooks import VETO_EVENTS, HookInput, HookResult, coerce_result

#: Interpreters a repository may name. Bare names only, so PATH rules apply the
#: same way for every run; an absolute path would let a config pin a binary the
#: reviewer never saw.
ALLOWED_INTERPRETERS: tuple[str, ...] = ("python3", "python", "node", "sh", "bash")

#: Keys one ``[[hooks]]`` entry may carry. ``command``/``args``/``env``/``shell``
#: are absent on purpose; an unknown key is an error, never an ignore.
_ALLOWED_KEYS = frozenset({"event", "script", "interpreter", "tool", "agent", "timeout_ms", "description"})

MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 10_000
DEFAULT_TIMEOUT_MS = 2_000
MAX_HOOKS = 16
MAX_STDOUT_BYTES = 64_000
MAX_STDERR_BYTES = 8_000
KILL_GRACE_SECONDS = 1.0
#: Child environment: enough to run an interpreter, nothing that could leak.
_CHILD_ENV_KEYS = ("PATH", "LANG", "LC_ALL")


class CommandHookError(ValueError):
    """A declared hook is unusable. Message is operator-facing; the CLI exits 64."""


@dataclass(frozen=True)
class CommandHook:
    """One validated ``[[hooks]]`` entry, ready to be registered."""

    name: str
    event: str
    script: Path
    interpreter: str | None = None
    tool: str | None = None
    agent: str | None = None
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Display form only: the resolved absolute script path is never printed."""
        return {
            "name": self.name,
            "event": self.event,
            "script": self.script.name,
            "interpreter": self.interpreter or "(direct exec)",
            "tool": self.tool,
            "agent": self.agent,
            "timeout_ms": self.timeout_ms,
        }


def _fail(message: str) -> "CommandHookError":
    return CommandHookError(message)


def _script_path(workspace: Path, raw: Any, *, index: int) -> Path:
    """Resolve a declared script inside the workspace, refusing anything else."""
    if not isinstance(raw, str) or not raw.strip():
        raise _fail(f"hooks[{index}]: 'script' must be a non-empty workspace-relative path")
    candidate = Path(raw.strip())
    if candidate.is_absolute():
        raise _fail(f"hooks[{index}]: 'script' must be workspace-relative, not absolute ({raw!r})")
    if ".." in candidate.parts:
        raise _fail(f"hooks[{index}]: 'script' must not contain '..' ({raw!r})")
    root_real = Path(os.path.realpath(str(workspace)))
    target = root_real / candidate
    resolved = Path(os.path.realpath(str(target)))
    try:
        resolved.relative_to(root_real)
    except ValueError:
        raise _fail(f"hooks[{index}]: 'script' resolves outside the workspace: {resolved}") from None
    if resolved.is_symlink() or (target.exists() and target.is_symlink()):
        raise _fail(f"hooks[{index}]: 'script' must not be a symlink ({raw!r})")
    if not resolved.is_file():
        raise _fail(f"hooks[{index}]: 'script' does not exist: {candidate}")
    return resolved


def parse_hooks(
    raw: Sequence[Any],
    *,
    workspace: str | Path,
    known_tools: Sequence[str] = (),
) -> tuple[CommandHook, ...]:
    """Validate a raw ``hooks`` list from the policy file. Raises on anything suspect."""
    root = Path(workspace)
    if not isinstance(raw, (list, tuple)):
        raise _fail("hooks must be an array of tables ([[hooks]])")
    if len(raw) > MAX_HOOKS:
        raise _fail(f"at most {MAX_HOOKS} hooks may be declared per workspace")
    hooks: list[CommandHook] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise _fail(f"hooks[{index}]: each entry must be a table")
        unknown = sorted(set(entry) - _ALLOWED_KEYS)
        if unknown:
            raise _fail(
                f"hooks[{index}]: unknown key(s) {', '.join(unknown)} - allowed: "
                f"{', '.join(sorted(_ALLOWED_KEYS))} (there is no 'command' key: hooks name a script, never a shell line)"
            )
        event = entry.get("event")
        if not isinstance(event, str) or event not in VETO_EVENTS:
            raise _fail(f"hooks[{index}]: 'event' must be one of {', '.join(VETO_EVENTS)} (only veto-capable events may be declared by a repository file)")
        script = _script_path(root, entry.get("script"), index=index)
        interpreter = entry.get("interpreter")
        if interpreter is not None:
            if not isinstance(interpreter, str) or not interpreter.strip():
                raise _fail(f"hooks[{index}]: 'interpreter' must be a non-empty string when present")
            if os.sep in interpreter.strip() or interpreter.strip() not in ALLOWED_INTERPRETERS:
                raise _fail(
                    f"hooks[{index}]: 'interpreter' must be one of {', '.join(ALLOWED_INTERPRETERS)} "
                    f"(no path separators, no absolute paths); got {interpreter!r}"
                )
            interpreter = interpreter.strip()
        else:
            interpreter = None
        tool = entry.get("tool")
        if tool is not None:
            if not isinstance(tool, str) or not tool.strip():
                raise _fail(f"hooks[{index}]: 'tool' must be a non-empty string when present")
            tool = tool.strip()
            if known_tools and tool not in set(known_tools):
                raise _fail(f"hooks[{index}]: 'tool' names an unknown tool {tool!r}")
        else:
            tool = None
        agent = entry.get("agent")
        if agent is not None and (not isinstance(agent, str) or not agent.strip()):
            raise _fail(f"hooks[{index}]: 'agent' must be a non-empty string when present")
        agent = agent.strip() if isinstance(agent, str) and agent.strip() else None
        timeout_ms = entry.get("timeout_ms", DEFAULT_TIMEOUT_MS)
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not MIN_TIMEOUT_MS <= timeout_ms <= MAX_TIMEOUT_MS:
            raise _fail(f"hooks[{index}]: 'timeout_ms' must be an integer between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}")
        description = entry.get("description", "")
        if not isinstance(description, str):
            raise _fail(f"hooks[{index}]: 'description' must be a string")
        name = f"hook:{event}:{candidate_name(entry, index)}"
        hooks.append(
            CommandHook(
                name=name,
                event=event,
                script=script,
                interpreter=interpreter,
                tool=tool,
                agent=agent,
                timeout_ms=int(timeout_ms),
                description=description.strip()[:600],
            )
        )
    return tuple(hooks)


def candidate_name(entry: Mapping[str, Any], index: int) -> str:
    raw = entry.get("script")
    if isinstance(raw, str) and raw.strip():
        return Path(raw.strip()).name
    return f"entry-{index}"


def build_callback(
    hook: CommandHook,
    *,
    workspace: str | Path,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> Callable[[HookInput], Any]:
    """Return the in-process hook that runs ``hook`` as a scrubbed subprocess.

    ``runner`` is the test seam (it replaces the whole spawn); production leaves
    it ``None`` and gets :func:`_run_bounded`.
    """
    root = Path(os.path.realpath(str(workspace)))

    def callback(hook_input: HookInput) -> HookResult:
        payload = hook_input.as_dict()
        argv = ([hook.interpreter] if hook.interpreter else []) + [str(hook.script)]
        try:
            completed = (runner or _run_bounded)(
                argv,
                cwd=str(root),
                input_text=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                timeout_s=hook.timeout_ms / 1000,
            )
        except subprocess.TimeoutExpired:
            # A hook that will not answer is a veto, not a green light.
            return HookResult.deny(
                f"{hook.name} timed out after {hook.timeout_ms}ms; veto-capable events fail closed"
            )
        except OSError as error:
            raise _fail(f"{hook.name} could not be executed: {error}") from error
        stdout = (completed.stdout or "")[:MAX_STDOUT_BYTES]
        stderr = (completed.stderr or "")[:MAX_STDERR_BYTES]
        code = int(getattr(completed, "returncode", 0) or 0)
        if code == 2:
            return HookResult.deny(f"{hook.name} denied: {stderr.strip() or 'no reason given'}")
        if code != 0:
            raise _fail(f"{hook.name} exited {code}: {stderr.strip() or 'no stderr'}")
        text = stdout.strip()
        if not text:
            return HookResult()
        try:
            verdict = json.loads(text)
        except (TypeError, ValueError) as error:
            raise _fail(f"{hook.name} printed a non-JSON verdict: {error}") from error
        return coerce_result(verdict)

    return callback


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: str,
    input_text: str,
    timeout_s: float,
) -> subprocess.CompletedProcess:
    """Run ``argv`` with a scrubbed environment, capped output, and group cleanup.

    A bare ``subprocess.run(timeout=...)`` reaps the child but not the children it
    spawned; a hook script that forks would leak a process per tool call. The
    process group is therefore created (``start_new_session``) and torn down
    TERM-then-KILL, matching the sidecar's cleanup rule.
    """
    env = {key: os.environ[key] for key in _CHILD_ENV_KEYS if key in os.environ}
    argv = list(argv)
    if argv and argv[0] in ALLOWED_INTERPRETERS:
        found = _which(argv[0])
        if found is None:
            raise _fail(f"interpreter {argv[0]!r} is not on PATH")
        argv[0] = found
    process = subprocess.Popen(  # noqa: S603 - argv is validated, no shell
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input_text, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _terminate_group(process)
        stdout, stderr = process.communicate(timeout=KILL_GRACE_SECONDS)
        raise subprocess.TimeoutExpired(argv, timeout_s, output=stdout, stderr=stderr) from None
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _terminate_group(process: subprocess.Popen) -> None:
    try:
        group = os.getpgid(process.pid)
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        process.kill()
        return
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, signal_number)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            process.wait(timeout=KILL_GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue


def _which(name: str) -> str | None:
    from shutil import which

    return which(name)


def register_into(registry: Any, hooks: Sequence[CommandHook], *, workspace: str | Path) -> tuple[str, ...]:
    """Attach validated hooks to a :class:`~hooks.HookRegistry`; returns their names."""
    for hook in hooks:
        registry.register(
            hook.event,
            build_callback(hook, workspace=workspace),
            name=hook.name,
            tool=hook.tool,
            agent=hook.agent,
        )
    return tuple(hook.name for hook in hooks)


def summarise(hooks: Sequence[CommandHook], *, enabled: bool) -> str:
    """One-line description for ``doctor``/``--dry-run`` output."""
    if not hooks:
        return "none declared"
    if not enabled:
        return f"{len(hooks)} declared but IGNORED (pass --enable-workspace-hooks to run them)"
    events = ", ".join(f"{hook.event}<-{hook.name.split(':')[-1]}" for hook in hooks[:MAX_HOOKS])
    return f"{len(hooks)} command hook(s): {events}"


__all__ = [
    "ALLOWED_INTERPRETERS",
    "DEFAULT_TIMEOUT_MS",
    "MAX_HOOKS",
    "CommandHook",
    "CommandHookError",
    "build_callback",
    "parse_hooks",
    "register_into",
    "summarise",
]
