"""Fail-closed Bubblewrap runner for the two contracted native scanners.

This module deliberately exposes no arbitrary command, URL, or flag interface.
The only scan entry point is :func:`run_native`; its tool argument selects one
of two fixed command lines.  A second, fixed-fixture probe is provided so the
caller can test the bwrap boundary before relying on a native scan.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ctypes
import json
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any, Mapping, Sequence


class NativeRunnerError(RuntimeError):
    """Raised before launch when a required, real isolation prerequisite is absent."""


# make_record() in native_contract.py imposes these hard parsing budgets.
HARD_MAX_STDOUT_BYTES = 2_097_152
HARD_MAX_STDERR_BYTES = 1_048_576
_STATUS_CAPTURE_BYTES = 65_536
_READ_CHUNK_BYTES = 65_536
_MAX_INPUT_FILES = 10_000
_MAX_ARGUMENT_BYTES = 1_000_000

# These are inherited by bwrap and the process it starts.  They are not a
# cgroup: aggregate cgroup accounting is intentionally not claimed.
ADDRESS_SPACE_LIMIT_BYTES = 1_073_741_824
FILE_SIZE_LIMIT_BYTES = 33_554_432
OPEN_FILE_LIMIT = 128
# This limit is inherited before bwrap creates its nested user namespace, so it
# must exceed concurrent processes already owned by the shared sandbox user.
# It still caps a scanner's process tree well below the host's normal limit.
PROCESS_LIMIT = 512
TMPFS_LIMIT_BYTES = 33_554_432
ROOT_TMPFS_LIMIT_BYTES = 67_108_864
SANDBOX_UID = 65_534
SANDBOX_GID = 65_534

# PR_SET_NO_NEW_PRIVS is deliberately set in the short-lived bwrap child before
# it execs.  It is inherited across every subsequent exec, including bwrap's
# reaper and scanner PID namespace.  Bubblewrap 0.9 has no equivalent command
# line switch.  Keep this Linux-only constant here rather than presenting an
# optional best-effort isolation feature.
_PR_SET_NO_NEW_PRIVS = 38

# Semgrep 1.181.0 packages its native semgrep-core and all of its non-system
# ELF dependencies under these exact in-venv paths.  The ordinary console
# script ultimately execs that core, but bwrap's mount setup prevents its
# $ORIGIN/libs RUNPATH from locating libtree-sitter.so.0.26 in this environment.
# Run the *packaged* native executable through the host loader instead.  Its
# --library-path applies to that one ELF exec; it is not LD_LIBRARY_PATH and
# therefore never changes Python's library lookup.
_SEMGREP_NATIVE_LIBS = "lib/python3.12/site-packages/semgrep/bin/libs"
_SEMGREP_NATIVE_CORE = "lib/python3.12/site-packages/semgrep/bin/semgrep-core"
_SEMGREP_DYNAMIC_LOADER = Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
_SEMGREP_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")

_RESOURCE_SIGNALS = {signal.SIGXCPU, signal.SIGXFSZ}


def _utc_stamp(value: datetime | None = None) -> str:
    moment = datetime.now(UTC) if value is None else value.astimezone(UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _require_int(value: object, name: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise NativeRunnerError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _existing_directory(value: Path, name: str) -> Path:
    if not isinstance(value, Path):
        raise NativeRunnerError(f"{name} must be a pathlib.Path")
    try:
        st = value.lstat()
    except OSError as exc:
        raise NativeRunnerError(f"{name} is unavailable: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise NativeRunnerError(f"{name} must be a non-symlink directory")
    return value.resolve(strict=True)


def _existing_file(value: Path, name: str, *, executable: bool = False, allow_symlink: bool = False) -> Path:
    try:
        st = value.lstat()
    except OSError as exc:
        raise NativeRunnerError(f"{name} is unavailable: {exc}") from exc
    if (not allow_symlink and stat.S_ISLNK(st.st_mode)) or not value.is_file():
        raise NativeRunnerError(f"{name} must be a regular file")
    if executable and not os.access(value, os.X_OK):
        raise NativeRunnerError(f"{name} is not executable")
    return value.resolve(strict=True) if not allow_symlink else value


def _safe_tree_files(input_root: Path) -> list[str]:
    """Reject links/special files and return the exact input file arguments.

    The runner bind-mounts one frozen directory.  Refusing all links and special
    files keeps that view from acquiring surprising references to another mount
    or hanging a scanner on a FIFO/device. Hard links are rejected: read-only
    mounting does not authenticate which source pathname originally owned them.
    """
    relative_files: list[str] = []
    for current_text, directories, filenames in os.walk(input_root, topdown=True, followlinks=False):
        current = Path(current_text)
        for directory in directories:
            candidate = current / directory
            try:
                mode = candidate.lstat().st_mode
            except OSError as exc:
                raise NativeRunnerError(f"cannot inspect input directory {candidate}: {exc}") from exc
            if not stat.S_ISDIR(mode):
                raise NativeRunnerError(f"input contains a link or non-directory: {candidate}")
        for filename in filenames:
            candidate = current / filename
            try:
                information = candidate.lstat()
                mode = information.st_mode
            except OSError as exc:
                raise NativeRunnerError(f"cannot inspect input file {candidate}: {exc}") from exc
            if not stat.S_ISREG(mode) or information.st_nlink != 1:
                raise NativeRunnerError(f"input contains a link or special file: {candidate}")
            relative_files.append(candidate.relative_to(input_root).as_posix())
            if len(relative_files) > _MAX_INPUT_FILES:
                raise NativeRunnerError("input contains too many files for a bounded scanner command")
    relative_files.sort()
    if not relative_files:
        raise NativeRunnerError("input directory is empty")
    if sum(len(name) + len("/input/") + 1 for name in relative_files) > _MAX_ARGUMENT_BYTES:
        raise NativeRunnerError("input filenames exceed the bounded scanner command budget")
    return relative_files


def _tool_file(tool_root: Path, relative: str, name: str, *, allow_symlink: bool = False) -> Path:
    # A resolved path outside the mount would not work from /tools.  The Python
    # executable is the one exception: conventional venvs link it to /usr/bin,
    # and /usr is deliberately mounted read-only.
    candidate = tool_root / relative
    checked = _existing_file(candidate, name, executable=False, allow_symlink=allow_symlink)
    if not allow_symlink:
        try:
            checked.relative_to(tool_root)
        except ValueError as exc:
            raise NativeRunnerError(f"{name} resolves outside tool_root") from exc
    return checked


def _tool_directory(tool_root: Path, relative: str, name: str) -> Path:
    """Return a non-link tool directory that remains below tool_root."""
    candidate = tool_root / relative
    checked = _existing_directory(candidate, name)
    try:
        checked.relative_to(tool_root)
    except ValueError as exc:
        raise NativeRunnerError(f"{name} resolves outside tool_root") from exc
    return checked


def _fixed_tool_command(tool: str, tool_root: Path, input_files: Sequence[str]) -> list[str]:
    if tool == "semgrep":
        _tool_file(tool_root, _SEMGREP_NATIVE_CORE, "semgrep native core")
        _tool_directory(tool_root, _SEMGREP_NATIVE_LIBS, "semgrep native library directory")
        _existing_file(_SEMGREP_DYNAMIC_LOADER, "semgrep native dynamic loader", executable=True)
        _existing_file(_SEMGREP_CA_BUNDLE, "semgrep public CA bundle")
        # console_scripts/entrypoint.py confirms that its osemgrep branch execs
        # the packaged semgrep-core with argv[0] = "osemgrep".  The explicit
        # loader preserves that argv0 and supplies just this core's venv-local
        # library directory.  Semgrep 1.181's native CLI needs --experimental
        # and takes scan roots directly (not the console-wrapper's ``scan``).
        # --no-exclude-minified-files is intentionally absent: 1.181.0 rejects
        # it.  Coverage remains fail-closed because the normalizer rejects any
        # Semgrep-reported skipped input.
        return [
            str(_SEMGREP_DYNAMIC_LOADER),
            "--argv0",
            "osemgrep",
            "--library-path",
            "/tools/" + _SEMGREP_NATIVE_LIBS,
            "/tools/" + _SEMGREP_NATIVE_CORE,
            "--experimental",
            "--config=/policy/semgrep.yaml",
            "--json",
            "--error",
            "--jobs=1",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--max-target-bytes=0",
            "--max-log-list-entries=0",
            *[f"/input/{relative}" for relative in input_files],
        ]
    if tool == "osv-scanner":
        _tool_file(tool_root, "osv-scanner", "osv-scanner executable")
        # The initial contracted dependency view is an exact, frozen Python
        # requirements lock file.  Supplying only -L prevents recursive source,
        # VCS, manifest, image, and build analysis.
        return [
            "/tools/osv-scanner",
            "scan",
            "source",
            "--lockfile=/input/requirements.txt",
            "--config=/policy/osv.toml",
            "--offline",
            "--no-resolve",
            "--no-call-analysis=all",
            "--no-ignore",
            "--all-packages",
            "--format=json",
        ]
    raise NativeRunnerError("tool must be exactly 'semgrep' or 'osv-scanner'")


def _safe_environment(tool: str, *, database_mounted: bool) -> dict[str, str]:
    # bwrap --clearenv enforces this inside the namespace.  The Popen environment
    # is separately scrubbed below, so neither bwrap nor the scanner inherits a
    # host credential, proxy, Python path, or Semgrep setting.
    env = {
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp",
        "PATH": "/tools/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PWD": "/input",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SEMGREP_SEND_METRICS": "off",
    }
    if tool == "osv-scanner":
        if not database_mounted:
            raise NativeRunnerError("osv-scanner requires a supplied, local offline database directory")
        env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = "/database"
        # OSV Scanner v2.7.0's vulnmatch/osvlocal component resolves the
        # supplied archive from /database/osv-scalibr/PyPI/all.zip.  Keeping
        # both variables prevents a fallback to a host XDG cache.
        env["OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY"] = "/database"
    return env


def _input_projection_arguments(input_root: Path, input_files: Sequence[str]) -> list[str]:
    """Build an empty, immutable /input view containing only fixed file paths.

    Mounting the candidate directory first and trying to overlay an empty
    ``.semgrepignore`` fails because a read-only bind cannot gain a child mount.
    A fresh tmpfs directory with individually read-only-bound regular files
    avoids that failure and prevents hidden candidate configuration files from
    changing Semgrep's explicit target scope.  The directory itself is 0555;
    bwrap performs its setup before the non-root scanner starts.
    """
    argv = ["--dir", "/input", "--chmod", "0555", "/input"]
    made_directories: set[str] = set()
    for relative in input_files:
        if type(relative) is not str or not relative:
            raise NativeRunnerError("internal input projection path is malformed")
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise NativeRunnerError("internal input projection path escapes /input")
        source = input_root.joinpath(*path.parts)
        _existing_file(source, "projected input file")
        parent = PurePosixPath()
        for part in path.parts[:-1]:
            parent /= part
            destination = "/input/" + parent.as_posix()
            if destination not in made_directories:
                argv.extend(("--dir", destination, "--chmod", "0555", destination))
                made_directories.add(destination)
        argv.extend(("--ro-bind", str(source), "/input/" + path.as_posix()))
    return argv


def _build_bwrap_command(
    *,
    bwrap_path: Path,
    input_root: Path,
    tool_root: Path | None,
    policy_file: Path | None,
    database_file: Path | None,
    empty_semgrepignore: Path | None,
    native_ca_bundle: Path | None,
    command: Sequence[str],
    input_files: Sequence[str],
    environment: Mapping[str, str],
    status_fd: int,
) -> list[str]:
    """Return the only allowed bwrap construction; command is internally fixed."""
    _existing_file(bwrap_path, "bwrap backend", executable=True, allow_symlink=True)
    if not command or any(type(part) is not str or "\x00" in part for part in command):
        raise NativeRunnerError("internal fixed command is malformed")

    argv = [
        str(bwrap_path),
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--assert-userns-disabled",
        "--uid",
        str(SANDBOX_UID),
        "--gid",
        str(SANDBOX_GID),
        "--cap-drop",
        "ALL",
        "--clearenv",
    ]
    for key, value in environment.items():
        argv.extend(("--setenv", key, value))
    # bwrap starts with an empty mount namespace; the explicit root tmpfs makes
    # that property independent of bwrap defaults.  Only /usr (runtime shared
    # libraries/interpreters) is host-mounted.  /bin, /lib, and /lib64 are
    # namespace-local symlinks into it.  There is deliberately no host /home,
    # /etc, /proc, /run, /sys, keyring, or socket mount.
    argv.extend(
        (
            "--size",
            str(ROOT_TMPFS_LIMIT_BYTES),
            "--tmpfs",
            "/",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--size",
            str(TMPFS_LIMIT_BYTES),
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/var",
            "--size",
            str(TMPFS_LIMIT_BYTES),
            "--tmpfs",
            "/var/tmp",
        )
    )
    argv.extend(_input_projection_arguments(input_root, input_files))
    if tool_root is not None:
        argv.extend(("--dir", "/tools", "--ro-bind", str(tool_root), "/tools"))
    if policy_file is not None:
        policy_destination = "/policy/semgrep.yaml" if policy_file.name == "semgrep.yaml" else "/policy/osv.toml"
        argv.extend(("--dir", "/policy", "--chmod", "0555", "/policy", "--ro-bind", str(policy_file), policy_destination))
    if empty_semgrepignore is not None:
        # Semgrep's default ignore list skips, for example, tests and vendor.
        # Overlaying this runner-created empty file prevents a candidate's
        # .semgrepignore from weakening the fixed explicit-file scope.
        argv.extend(("--ro-bind", str(empty_semgrepignore), "/input/.semgrepignore"))
    if native_ca_bundle is not None:
        # Semgrep's native OCaml TLS initialization requires a public trust
        # anchor even when metrics are disabled and the network namespace is
        # absent.  This is the single CA *certificate bundle*, not host /etc,
        # an account file, or any private key material.
        argv.extend(
            (
                "--dir",
                "/etc",
                "--dir",
                "/etc/ssl",
                "--dir",
                "/etc/ssl/certs",
                "--chmod",
                "0555",
                "/etc",
                "--chmod",
                "0555",
                "/etc/ssl",
                "--chmod",
                "0555",
                "/etc/ssl/certs",
                "--ro-bind",
                str(native_ca_bundle),
                "/etc/ssl/certs/ca-certificates.crt",
            )
        )
    if database_file is not None:
        # OSV 2.7's vulnmatch/osvlocal reads this exact archive below its
        # ``osv-scalibr`` cache component.  Mount no database directory (which
        # could expose unrelated ecosystems/files), only its PyPI all.zip.
        argv.extend(
            (
                "--dir",
                "/database",
                "--dir",
                "/database/osv-scalibr",
                "--dir",
                "/database/osv-scalibr/PyPI",
                "--chmod",
                "0555",
                "/database",
                "--chmod",
                "0555",
                "/database/osv-scalibr",
                "--chmod",
                "0555",
                "/database/osv-scalibr/PyPI",
                "--ro-bind",
                str(database_file),
                "/database/osv-scalibr/PyPI/all.zip",
            )
        )
    argv.extend(("--chdir", "/input", "--json-status-fd", str(status_fd), "--", *command))
    return argv


def _set_no_new_privileges() -> None:
    """Fail closed unless Linux records PR_SET_NO_NEW_PRIVS for this process."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "PR_SET_NO_NEW_PRIVS could not be set")


def _preexec_limits(cpu_seconds: int) -> None:
    """Set inherited no-new-privileges and resource limits before bwrap exec."""
    _set_no_new_privileges()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT_BYTES, ADDRESS_SPACE_LIMIT_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_SIZE_LIMIT_BYTES, FILE_SIZE_LIMIT_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (OPEN_FILE_LIMIT, OPEN_FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_NPROC, (PROCESS_LIMIT, PROCESS_LIMIT))


def _bounded_pipe_reader(
    pipe: Any,
    destination: bytearray,
    limit: int,
    overflow: threading.Event | None,
    truncated: dict[str, bool],
    stream_name: str,
) -> None:
    try:
        while True:
            chunk = pipe.read1(_READ_CHUNK_BYTES)
            if not chunk:
                return
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated[stream_name] = True
                if overflow is not None:
                    overflow.set()
            # Deliberately continue draining after overflow.  It prevents a
            # blocked writer while the supervisor kills the PID namespace, but
            # destination remains strictly bounded.
    finally:
        try:
            pipe.close()
        except OSError:
            pass


def _status_reader(fd: int, destination: bytearray, truncated: dict[str, bool]) -> None:
    try:
        with os.fdopen(fd, "rb", buffering=0) as pipe:
            while True:
                chunk = pipe.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = _STATUS_CAPTURE_BYTES - len(destination)
                if remaining > 0:
                    destination.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated["status"] = True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _terminate_namespace(process: subprocess.Popen[bytes]) -> list[str]:
    """Terminate only the runner-created process group, then force-kill it."""
    actions: list[str] = []
    if process.poll() is not None:
        return actions
    for sig, label, grace_seconds in ((signal.SIGTERM, "SIGTERM", 0.25), (signal.SIGKILL, "SIGKILL", 0.0)):
        if process.poll() is not None:
            break
        try:
            os.killpg(process.pid, sig)
            actions.append(label)
        except ProcessLookupError:
            break
        if grace_seconds:
            deadline = time.monotonic() + grace_seconds
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
    return actions


def _parse_status(raw: bytes, was_truncated: bool) -> tuple[bool, bool, int]:
    if was_truncated:
        return False, False, 0
    launched = False
    exited = False
    valid_lines = 0
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(item) is not dict:
            continue
        valid_lines += 1
        if type(item.get("child-pid")) is int and item["child-pid"] > 0:
            launched = True
        if type(item.get("exit-code")) is int:
            exited = True
    return launched, exited, valid_lines


@dataclass(frozen=True)
class _ExecutionResult:
    stdout: bytes
    stderr: bytes
    execution: dict[str, Any]
    isolation: dict[str, Any]
    metadata: dict[str, Any]


def _execute_bwrap(
    argv: list[str],
    *,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    supervisor_env: Mapping[str, str] | None = None,
) -> _ExecutionResult:
    """Launch an already-fixed bwrap argv with a wall-clock/PID-tree deadline."""
    start_wall = datetime.now(UTC)
    start_monotonic = time.monotonic()
    stdout = bytearray()
    stderr = bytearray()
    status = bytearray()
    truncation = {"stdout": False, "stderr": False, "status": False}
    overflow = threading.Event()
    status_read_fd, status_write_fd = os.pipe()
    # _build_bwrap_command is intentionally the only producer of this flag.
    # Replace its construction-only descriptor with the descriptor inherited
    # by this exact child process; never rely on descriptor-number reuse.
    try:
        status_index = argv.index("--json-status-fd")
        argv = list(argv)
        argv[status_index + 1] = str(status_write_fd)
    except (ValueError, IndexError):
        os.close(status_read_fd)
        os.close(status_write_fd)
        raise NativeRunnerError("internal bwrap status-fd wiring is malformed")
    launch_env = dict(supervisor_env) if supervisor_env is not None else {"NORTHSTAR_SUPERVISOR": "runner"}
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=launch_env,
            close_fds=True,
            pass_fds=(status_write_fd,),
            start_new_session=True,
            preexec_fn=lambda: _preexec_limits(timeout_seconds),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        os.close(status_read_fd)
        os.close(status_write_fd)
        raise NativeRunnerError(f"bwrap backend could not launch; no process fallback is allowed: {exc}") from exc
    finally:
        try:
            os.close(status_write_fd)
        except OSError:
            pass

    assert process.stdout is not None and process.stderr is not None
    stdout_thread = threading.Thread(
        target=_bounded_pipe_reader,
        args=(process.stdout, stdout, max_stdout_bytes, overflow, truncation, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_bounded_pipe_reader,
        args=(process.stderr, stderr, max_stderr_bytes, overflow, truncation, "stderr"),
        daemon=True,
    )
    status_thread = threading.Thread(target=_status_reader, args=(status_read_fd, status, truncation), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    status_thread.start()

    timed_out = False
    output_limit_triggered = False
    kill_actions: list[str] = []
    while process.poll() is None:
        if overflow.is_set():
            output_limit_triggered = True
            kill_actions = _terminate_namespace(process)
            break
        if time.monotonic() - start_monotonic >= timeout_seconds:
            timed_out = True
            kill_actions = _terminate_namespace(process)
            break
        time.sleep(0.01)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        # A second, forced group kill is still the bwrap/PID-namespace path; a
        # hung supervisor is not silently converted to an ordinary process run.
        kill_actions.extend(_terminate_namespace(process))
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as nested:
            raise NativeRunnerError("bwrap supervisor did not terminate after PID-namespace kill") from nested
        raise NativeRunnerError("bwrap supervisor required a second PID-namespace kill") from exc
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        status_thread.join(timeout=5)

    if stdout_thread.is_alive() or stderr_thread.is_alive() or status_thread.is_alive():
        raise NativeRunnerError("bounded capture thread did not terminate")

    sandbox_launched, sandbox_exited, status_line_count = _parse_status(bytes(status), truncation["status"])
    exit_code = process.returncode
    resource_exhausted = bool(exit_code is not None and exit_code < 0 and -exit_code in _RESOURCE_SIGNALS)
    if timed_out:
        status_name = "timed_out"
    elif output_limit_triggered or truncation["stdout"] or truncation["stderr"] or not sandbox_launched or not sandbox_exited:
        status_name = "error"
    elif resource_exhausted:
        status_name = "resource_exhausted"
    else:
        # Non-zero scanner exits remain completed executions: the normalizer
        # validates their JSON/error consistency and fails closed if required.
        status_name = "completed"

    end_wall = datetime.now(UTC)
    duration_ms = max(0, round((time.monotonic() - start_monotonic) * 1000))
    if sandbox_launched:
        isolation = {
            "backend": "bwrap",
            "read_only_inputs": True,
            "network": "denied",
            "credentials": "none",
            "project_code_executed": False,
            "non_root": True,
        }
    else:
        # We do not assert bwrap isolation simply because an executable named
        # bwrap was spawned.  Absence of the status child record makes the run
        # unusable to normalizers and visibly fails closed.
        isolation = {
            "backend": "unknown",
            "read_only_inputs": False,
            "network": "unknown",
            "credentials": "unknown",
            "project_code_executed": False,
            "non_root": False,
        }
    execution = {
        "status": status_name,
        "started_at": _utc_stamp(start_wall),
        "finished_at": _utc_stamp(end_wall),
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "resource_exhausted": resource_exhausted,
        "output_truncated": bool(truncation["stdout"] or truncation["stderr"] or output_limit_triggered),
    }
    metadata = {
        "fixed_backend": "bwrap",
        "bwrap_status_child_reported": sandbox_launched,
        "bwrap_status_exit_reported": sandbox_exited,
        "bwrap_status_valid_line_count": status_line_count,
        "bwrap_status_truncated": truncation["status"],
        "output_limit_triggered": output_limit_triggered,
        "deadline_kill_signals": kill_actions,
        "resource_limits": {
            "enforced_via": "inherited-setrlimit",
            "cpu_seconds": timeout_seconds,
            "address_space_bytes": ADDRESS_SPACE_LIMIT_BYTES,
            "file_size_bytes": FILE_SIZE_LIMIT_BYTES,
            "open_files": OPEN_FILE_LIMIT,
            "processes": PROCESS_LIMIT,
            "core_bytes": 0,
            "cgroup_aggregate_budget": "not-configured",
        },
    }
    return _ExecutionResult(bytes(stdout), bytes(stderr), execution, isolation, metadata)


def run_native(
    tool: str,
    *,
    tool_root: Path,
    input_dir: Path,
    policy_dir: Path,
    database_dir: Path | None = None,
    bwrap_path: Path,
    timeout_seconds: int = 120,
    max_stdout_bytes: int = HARD_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = HARD_MAX_STDERR_BYTES,
) -> dict[str, Any]:
    """Run one contracted scanner through a real bwrap backend, or fail before launch.

    No process-mode fallback exists.  The returned ``execution`` and
    ``isolation`` fields are host-supervised facts; callers must still make their
    normalizer reject error, timeout, truncation, or unknown-isolation records.
    """
    if tool not in ("semgrep", "osv-scanner"):
        raise NativeRunnerError("tool must be exactly 'semgrep' or 'osv-scanner'")
    timeout_seconds = _require_int(timeout_seconds, "timeout_seconds", minimum=1, maximum=86_400)
    max_stdout_bytes = _require_int(
        max_stdout_bytes, "max_stdout_bytes", minimum=1, maximum=HARD_MAX_STDOUT_BYTES
    )
    max_stderr_bytes = _require_int(
        max_stderr_bytes, "max_stderr_bytes", minimum=1, maximum=HARD_MAX_STDERR_BYTES
    )
    input_root = _existing_directory(input_dir, "input_dir")
    policy_root = _existing_directory(policy_dir, "policy_dir")
    tools_root = _existing_directory(tool_root, "tool_root")
    bwrap_checked = _existing_file(bwrap_path, "bwrap backend", executable=True, allow_symlink=True)
    # For a symlink bwrap the supplied path (rather than its resolved host path)
    # is executed; it remains a trusted host prerequisite, never a scanner arg.
    bwrap_for_exec = bwrap_path if bwrap_path.is_symlink() else bwrap_checked
    input_files = _safe_tree_files(input_root)
    policy_name = "semgrep.yaml" if tool == "semgrep" else "osv.toml"
    policy_file = _existing_file(policy_root / policy_name, f"policy {policy_name}")

    database_file: Path | None = None
    if tool == "osv-scanner":
        if database_dir is None:
            raise NativeRunnerError("osv-scanner requires database_dir for a fail-closed offline scan")
        database_root = _existing_directory(database_dir, "database_dir")
        database_file = _existing_file(
            database_root / "osv-scanner" / "PyPI" / "all.zip",
            "offline PyPI database all.zip",
        )
        lockfile = input_root / "requirements.txt"
        _existing_file(lockfile, "frozen OSV requirements.txt")
    elif database_dir is not None:
        raise NativeRunnerError("database_dir is only valid for osv-scanner")

    if tool == "semgrep" and any(PurePosixPath(name).name == ".semgrepignore" for name in input_files):
        raise NativeRunnerError("Semgrep input scope may not include .semgrepignore")
    fixed_command = _fixed_tool_command(tool, tools_root, input_files)
    with tempfile.TemporaryDirectory(prefix="northstar-empty-semgrepignore-") as temporary_text:
        empty_semgrepignore: Path | None = None
        if tool == "semgrep":
            empty_semgrepignore = Path(temporary_text) / ".semgrepignore"
            empty_semgrepignore.write_bytes(b"")
        status_read_fd, status_write_fd = os.pipe()
        try:
            argv = _build_bwrap_command(
                bwrap_path=bwrap_for_exec,
                input_root=input_root,
                tool_root=tools_root,
                policy_file=policy_file,
                database_file=database_file,
                empty_semgrepignore=empty_semgrepignore,
                native_ca_bundle=_SEMGREP_CA_BUNDLE if tool == "semgrep" else None,
                command=fixed_command,
                input_files=input_files if tool == "semgrep" else ("requirements.txt",),
                environment=_safe_environment(tool, database_mounted=database_file is not None),
                status_fd=status_write_fd,
            )
        finally:
            os.close(status_read_fd)
            os.close(status_write_fd)
        # _execute_bwrap allocates its own status pipe because the bwrap process
        # must inherit that FD.  Its descriptor replacement is explicit, not
        # dependent on numeric FD reuse.  The temporary ignore file stays alive
        # until the bwrap child has exited.
        result = _execute_bwrap(
            argv,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
    metadata = dict(result.metadata)
    metadata.update(
        {
            "tool": tool,
            "fixed_command": fixed_command,
            "requested_input_files": input_files if tool == "semgrep" else ["requirements.txt"],
            "semgrep_scope_protection": (
                "fresh 0555 /input projection of explicit regular files; empty trusted "
                ".semgrepignore; --no-git-ignore; --max-target-bytes=0; normalizer "
                "must reject reported skipped files"
                if tool == "semgrep"
                else None
            ),
            "actual_detection_capability": (
                {
                    "engine": "Semgrep OSS 1.181.0 via the installed console script and packaged semgrep-core",
                    "scope": "local policy rules over explicit projected source files only",
                    "native_library_resolution": "trusted ld-linux --library-path for packaged semgrep-core only; LD_LIBRARY_PATH is unset and Python is not started",
                    "runtime_public_data": "single read-only CA certificate bundle required by the native TLS initializer; network remains unshared",
                    "not_provided": [
                        "remote rules",
                        "Semgrep Pro or secrets engines",
                        "project code execution",
                        "proof that every parser-supported file is scannable",
                    ],
                }
                if tool == "semgrep"
                else {
                    "engine": "OSV-Scanner 2.7.0",
                    "scope": "one explicit requirements.txt lockfile against the mounted local PyPI all.zip database",
                    "not_provided": [
                        "network database access",
                        "transitive dependency resolution",
                        "call analysis or build execution",
                        "other package ecosystems or lockfile formats",
                    ],
                }
            ),
        }
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "execution": result.execution,
        "isolation": result.isolation,
        "metadata": metadata,
    }


_PROBE_PROGRAM = r"""
import json
import os
import socket
import sys

answer = {}
try:
    with open('/input/probe.txt', 'wb') as writable:
        writable.write(b'blocked-write')
    answer['input_write_denied'] = False
except OSError:
    answer['input_write_denied'] = True
try:
    with open(sys.argv[1], 'rb') as secret:
        secret.read(1)
    answer['host_secret_invisible'] = False
except OSError:
    answer['host_secret_invisible'] = True
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    sock.connect(('127.0.0.1', int(sys.argv[2])))
    answer['host_socket_denied'] = False
except OSError:
    answer['host_socket_denied'] = True
finally:
    sock.close()
answer['fake_secret_absent'] = 'NORTHSTAR_FAKE_SECRET' not in os.environ
print(json.dumps(answer, sort_keys=True, separators=(',', ':')))
sys.exit(0 if all(answer.values()) else 70)
"""


def run_isolation_probes(*, bwrap_path: Path, timeout_seconds: int = 15) -> dict[str, Any]:
    """Run four fixed local-fixture negative probes through the same bwrap policy.

    The function creates its own temporary file and loopback listener.  It does
    not accept a command, URL, host, port, credential, or external target.
    ``NORTHSTAR_FAKE_SECRET`` exists only in bwrap's supervisor environment and
    must be removed by ``--clearenv`` before the probe executes.
    """
    timeout_seconds = _require_int(timeout_seconds, "timeout_seconds", minimum=1, maximum=86_400)
    bwrap_checked = _existing_file(bwrap_path, "bwrap backend", executable=True, allow_symlink=True)
    bwrap_for_exec = bwrap_path if bwrap_path.is_symlink() else bwrap_checked
    with tempfile.TemporaryDirectory(prefix="northstar-native-runner-probe-") as root_text:
        root = Path(root_text)
        input_root = root / "input"
        input_root.mkdir(mode=0o700)
        (input_root / "probe.txt").write_bytes(b"immutable fixture\n")
        secret = root / "host-secret.txt"
        secret.write_bytes(b"fixture-only-not-a-credential\n")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            status_read_fd, status_write_fd = os.pipe()
            try:
                argv = _build_bwrap_command(
                    bwrap_path=bwrap_for_exec,
                    input_root=input_root,
                    tool_root=None,
                    policy_file=None,
                    database_file=None,
                    empty_semgrepignore=None,
                    native_ca_bundle=None,
                    command=("/usr/bin/python3", "-c", _PROBE_PROGRAM, str(secret), str(port)),
                    input_files=("probe.txt",),
                    environment={
                        "HOME": "/tmp",
                        "TMPDIR": "/tmp",
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "PWD": "/input",
                    },
                    status_fd=status_write_fd,
                )
            finally:
                os.close(status_read_fd)
                os.close(status_write_fd)
            result = _execute_bwrap(
                argv,
                timeout_seconds=timeout_seconds,
                max_stdout_bytes=16_384,
                max_stderr_bytes=16_384,
                supervisor_env={"NORTHSTAR_FAKE_SECRET": "fixture-only-not-a-credential"},
            )
        finally:
            listener.close()

    observed: dict[str, bool] = {}
    try:
        parsed = json.loads(result.stdout)
        if type(parsed) is dict and set(parsed) == {
            "input_write_denied",
            "host_secret_invisible",
            "host_socket_denied",
            "fake_secret_absent",
        } and all(type(value) is bool for value in parsed.values()):
            observed = parsed
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    passed = (
        result.execution["status"] == "completed"
        and result.execution["exit_code"] == 0
        and result.isolation["backend"] == "bwrap"
        and len(observed) == 4
        and all(observed.values())
    )
    return {
        "passed": passed,
        "probes": observed,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "execution": result.execution,
        "isolation": result.isolation,
        "metadata": result.metadata,
    }
