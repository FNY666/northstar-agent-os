"""Repository-declared lifecycle hooks: the governed subset of a "command hook".

Claude Code let a settings file run a shell command at a lifecycle event, and it
works well for teams - policy review happens in a pull request, not in a Python
file. Northstar wants the same reach, but a workspace-declared hook is *code the
agent's environment can influence*, so this module implements the narrow,
fail-closed version of the idea:

- **Veto-capable events, plus ``Stop`` checks.** Repository hooks may veto a tool,
  prompt, session start, compaction, or delegation, and a ``Stop`` script may block
  completion until its check passes. Observation hooks such as ``PostToolUse`` are
  refused because a repository file cannot add a new authorization path.
- **No command-line fields.** The schema has no ``command`` or ``args`` string;
  it runs a workspace-relative ``script`` with an allowlisted interpreter. The
  script is executable code and may run project commands, so it must be reviewed
  before enabling hooks.
- **Workspace containment, symlink-first.** The script is resolved with the same
  rule the file tools use: it must live inside the workspace root after
  ``realpath``, be an existing regular file, and not be a symlink. A skill or
  config that points outside the run is refused, never followed.
- **Bounded and killed.** Byte-capped pipes, a bounded timeout, and TERM-then-KILL
  of the hook's process group, including children after the leader exits. Descendants
  that deliberately leave that group require external OS containment; hooks are not
  a sandbox.
- **Nothing is inherited.** The child gets a scrubbed environment (``PATH`` and
  ``LANG`` only) and the workspace as cwd, so model credentials never cross into
  hook code.
- **Off by default.** ``--enable-workspace-hooks`` is required. Cloning a
  repository must not mean executing it.
- **Fail closed.** A timeout or execution error denies a veto event or blocks a
  ``Stop`` check. Non-zero exits block ``Stop``; malformed verdicts deny veto hooks.

Veto hooks receive a JSON request on stdin (``HookInput.as_dict()``) and may print
an optional JSON verdict on stdout, coerced by :func:`hooks.coerce_result`. A
``Stop`` check uses its exit status as the verdict, never parses stdout as a hook
response, and retains only a bounded tail to help the agent repair a failed check.
"""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from hooks import VETO_EVENTS, HookInput, HookResult, coerce_result

#: Interpreters a repository may name. Bare names only, so PATH rules apply the
#: same way for every run; an absolute path would let a config pin a binary the
#: reviewer never saw.
ALLOWED_INTERPRETERS: tuple[str, ...] = ("python3", "python", "node", "sh", "bash")

#: Workspace hooks may also use Stop to run an explicit end-of-run check. Plugin
#: manifests remain restricted to VETO_EVENTS in plugin_manifest.py.
WORKSPACE_HOOK_EVENTS: tuple[str, ...] = (*VETO_EVENTS, "Stop")

#: Keys one ``[[hooks]]`` entry may carry. ``command``/``args``/``env``/``shell``
#: are absent on purpose; an unknown key is an error, never an ignore.
_ALLOWED_KEYS = frozenset({"event", "script", "interpreter", "tool", "agent", "timeout_ms", "description"})

MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 10_000
MAX_STOP_TIMEOUT_MS = 120_000
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
    script_digest: str = ""
    entry_index: int = 0

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
    reviewed_digests: Mapping[str, str] | None = None,
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
        if not isinstance(event, str) or event not in WORKSPACE_HOOK_EVENTS:
            raise _fail(f"hooks[{index}]: 'event' must be one of {', '.join(WORKSPACE_HOOK_EVENTS)} (repository hooks may veto actions or block Stop)")
        script = _script_path(root, entry.get("script"), index=index)
        script_bytes = script.read_bytes()
        relative_script = script.relative_to(Path(workspace).resolve()).as_posix()
        expected_digest = (reviewed_digests or {}).get(relative_script)
        plugin_owned = relative_script.startswith(".northstar/plugins/")
        if plugin_owned and not expected_digest:
            raise _fail(f"hooks[{index}]: plugin hook has no reviewed content digest")
        if expected_digest is not None:
            if hashlib.sha256(script_bytes).hexdigest() != expected_digest:
                raise _fail(f"hooks[{index}]: script changed since bundle review; refusing hook")
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
        timeout_limit = MAX_STOP_TIMEOUT_MS if event == "Stop" else MAX_TIMEOUT_MS
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not MIN_TIMEOUT_MS <= timeout_ms <= timeout_limit:
            raise _fail(f"hooks[{index}]: 'timeout_ms' must be an integer between {MIN_TIMEOUT_MS} and {timeout_limit} for {event}")
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
                script_digest=hashlib.sha256(script_bytes).hexdigest(),
                entry_index=index,
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
    """Return the in-process hook that runs a digest-checked script.

    The reviewed bytes are captured at registration. Before each dispatch the script path
    is re-read and checked against that digest; a changed file is vetoed before reaching
    the runner. Execution uses the original path/interpreter semantics for compatibility.
    A hostile same-user writer could still race the final digest read against the OS open in
    the subprocess; deployments requiring that stronger property should run hooks from an
    immutable snapshot or an OS-enforced read-only tree.
    """
    root = Path(os.path.realpath(str(workspace)))

    def stop_check_result(
        *,
        passed: bool,
        started: float,
        turn_index: int,
        exit_code: int | None = None,
        timed_out: bool = False,
        reason: str = "",
        workspace_binding: Mapping[str, Any] | None = None,
    ) -> HookResult:
        check = {
            "name": hook.name,
            "id": f"{hook.name}#{hook.entry_index}",
            "script": hook.script.relative_to(root).as_posix(),
            "status": "passed" if passed else "failed",
            "turn_index": turn_index,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        }
        if workspace_binding is not None:
            check["workspace_binding"] = dict(workspace_binding)
        result_data = {"workspace_check": check}
        if passed:
            return HookResult(decision="allow", data=result_data)
        return HookResult(decision="block", reason=reason or f"{hook.name} check failed", data=result_data)

    def callback(hook_input: HookInput) -> HookResult:
        payload = hook_input.as_dict()
        started = time.monotonic()
        is_stop_check = hook.event == "Stop"
        workspace_before: Any = None

        def stop_outcome(**kwargs: Any) -> HookResult:
            binding = None
            if workspace_before is not None:
                from coding_evidence import snapshot_workspace, workspace_check_binding

                binding = workspace_check_binding(workspace_before, snapshot_workspace(root))
            return stop_check_result(
                started=started,
                turn_index=hook_input.turn_index,
                workspace_binding=binding,
                **kwargs,
            )

        # Workspace Stop checks verify the completed top-level task. A child agent
        # returning its partial result must not launch the project suite early.
        if is_stop_check and hook_input.depth > 0:
            return HookResult()
        try:
            current = hook.script.read_bytes()
        except OSError as error:
            if is_stop_check:
                return stop_outcome(passed=False, reason=f"{hook.name} script is no longer readable: {error}")
            return HookResult.deny(f"{hook.name} script is no longer readable: {error}")
        if hashlib.sha256(current).hexdigest() != hook.script_digest:
            if is_stop_check:
                return stop_outcome(passed=False, reason=f"{hook.name} script changed since registration; refusing check")
            return HookResult.deny(f"{hook.name} script changed since registration; refusing dispatch")
        if is_stop_check:
            from coding_evidence import snapshot_workspace

            workspace_before = snapshot_workspace(root)
        # Preserve the original path/interpreter semantics after verifying current bytes.
        # Residual: a same-user adversary can still race this check against the OS open in Popen.
        argv = ([hook.interpreter] if hook.interpreter else []) + [str(hook.script)]
        try:
            run = runner or _run_bounded
            run_kwargs: dict[str, Any] = {
                "cwd": str(root),
                "input_text": json.dumps(payload, ensure_ascii=False, sort_keys=True),
                "timeout_s": hook.timeout_ms / 1000,
            }
            if runner is None:
                run_kwargs["capture_stdout"] = not is_stop_check
                if is_stop_check:
                    run_kwargs["stdout_tail_bytes"] = MAX_STDERR_BYTES
            completed = run(argv, **run_kwargs)
        except subprocess.TimeoutExpired:
            # A hook that will not answer is a veto, not a green light.
            if is_stop_check:
                return stop_outcome(
                    passed=False,
                    timed_out=True,
                    reason=f"{hook.name} check timed out after {hook.timeout_ms}ms",
                )
            return HookResult.deny(
                f"{hook.name} timed out after {hook.timeout_ms}ms; veto-capable events fail closed"
            )
        except OSError as error:
            if is_stop_check:
                return stop_outcome(passed=False, reason=f"{hook.name} could not be executed: {error}")
            raise _fail(f"{hook.name} could not be executed: {error}") from error
        except Exception as error:  # output caps, cleanup failures, and decode errors
            if is_stop_check:
                return stop_outcome(passed=False, reason=f"{hook.name} could not complete: {type(error).__name__}: {error}")
            raise
        stdout = (completed.stdout or "")[:MAX_STDOUT_BYTES]
        stderr = (completed.stderr or "")[:MAX_STDERR_BYTES]
        code = int(getattr(completed, "returncode", 0) or 0)
        if is_stop_check:
            if code == 0:
                return stop_outcome(passed=True, exit_code=code)
            return stop_outcome(
                passed=False,
                exit_code=code,
                reason=f"{hook.name} check exited {code}: "
                + (("\n".join(part.strip() for part in (stdout, stderr) if part.strip()))[-MAX_STDERR_BYTES:] or "no output"),
            )
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
        result = coerce_result(verdict)
        return result

    return callback


def _run_bounded(
    argv: Sequence[str],
    *,
    cwd: str,
    input_text: str,
    timeout_s: float,
    capture_stdout: bool = True,
    stdout_tail_bytes: int = 0,
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
    deadline = time.monotonic() + timeout_s
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_STDOUT_BYTES, "stderr": MAX_STDERR_BYTES}
    pending = memoryview(input_text.encode("utf-8"))
    selector = selectors.DefaultSelector()
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 - argv is validated, no shell
            argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        if pending:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout_s)
            for key, _mask in selector.select(min(.05, remaining)):
                stream, name = key.fileobj, key.data
                if name == "stdin":
                    try:
                        written = os.write(stream.fileno(), pending[:4096])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        pending = pending[:0]
                    else:
                        pending = pending[written:]
                    if not pending:
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if name == "stdout" and not capture_stdout:
                    if stdout_tail_bytes > 0:
                        captured[name].extend(chunk)
                        if len(captured[name]) > stdout_tail_bytes:
                            del captured[name][:-stdout_tail_bytes]
                    continue
                if len(captured[name]) + len(chunk) > limits[name]:
                    raise _fail(f"hook output {name} exceeds byte limit {limits[name]}; refusing verdict")
                captured[name].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout_s)
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(argv, timeout_s) from None
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_errors = []
        try:
            selector.close()
        except Exception as error:
            cleanup_errors.append(error)
        if process is not None:
            # Release full-pipe writers before reaping (iSH can defer pending signals).
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    if stream is not None and not stream.closed:
                        stream.close()
                except Exception as error:
                    cleanup_errors.append(error)
            try:
                _terminate_group(process)
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            detail = "hook cleanup failed: " + ", ".join(type(error).__name__ for error in cleanup_errors)
            if primary_error is None:
                raise _fail(detail) from cleanup_errors[0]
            if hasattr(primary_error, "add_note"):
                primary_error.add_note(detail)
            else:  # Python 3.10: preserve the original exception, with explicit context.
                primary_error.__context__ = cleanup_errors[0]
    stdout_errors = "strict" if capture_stdout else "replace"
    stdout = captured["stdout"].decode("utf-8", errors=stdout_errors)
    stderr = captured["stderr"].decode("utf-8")
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _terminate_group(process: subprocess.Popen) -> None:
    # start_new_session=True makes pid the group id even after the leader exits.
    # wait(leader) returning does not prove its group is empty.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except (PermissionError, AttributeError, OSError):
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except (PermissionError, AttributeError, OSError):
        if process.poll() is None:
            process.kill()
    if process.poll() is None:
        process.wait(timeout=KILL_GRACE_SECONDS)


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
    "MAX_STOP_TIMEOUT_MS",
    "CommandHook",
    "CommandHookError",
    "WORKSPACE_HOOK_EVENTS",
    "build_callback",
    "parse_hooks",
    "register_into",
    "summarise",
]
