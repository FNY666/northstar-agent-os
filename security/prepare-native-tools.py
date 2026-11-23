#!/usr/bin/env python3
"""Prepare pinned native scanner artifacts without scanning, signing, or using apt.

This program publishes a new tool root only after all preparation succeeds.  It
never touches an existing --output and never invokes an operator supplied bwrap
binary.  Semgrep installation is offline from an operator supplied binary-wheel
wheelhouse; this keeps every network transfer in this program under the bounded
streaming downloader below.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import Request, urlopen

SCHEMA = "northstar.native-tool-provisioning.v1"
SEMGREP_VERSION = "1.181.0"
OSV_VERSION = "2.7.0"
OSV_LINUX_AMD64_URL = (
    "https://github.com/google/osv-scanner/releases/download/v2.7.0/"
    "osv-scanner_linux_amd64"
)
OSV_LINUX_AMD64_SHA256 = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"
OSV_PYPI_ALL_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
NETWORK_TIMEOUT_SECONDS = 90
OSV_BINARY_MAX_BYTES = 64 * 1024 * 1024
OSV_DATABASE_MAX_BYTES = 512 * 1024 * 1024
BWRAP_MAX_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
VERSION_OUTPUT_MAX_BYTES = 16 * 1024


class ProvisionError(RuntimeError):
    """An input, network transfer, subprocess, or publication invariant failed."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write a fresh staging file atomically; staging paths must not already exist."""
    if os.path.lexists(path):
        raise ProvisionError(f"refusing to overwrite staging artifact: {path.name}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _parse_content_length(headers, maximum: int) -> None:
    value = headers.get("Content-Length")
    if value is None:
        return
    try:
        length = int(value)
    except ValueError as error:
        raise ProvisionError("server returned a malformed Content-Length") from error
    if length < 0 or length > maximum:
        raise ProvisionError("network response exceeds its byte budget")


def download_to_file(url: str, destination: Path, *, expected_sha256: str | None,
                     maximum_bytes: int, timeout_seconds: int,
                     require_last_modified: bool = False) -> dict:
    """Bound one HTTPS response, hash it, and atomically publish it inside staging.

    ``expected_sha256`` is an integrity pin only.  It is deliberately not
    represented as a publisher signature in the returned record.
    """
    if not url.startswith("https://"):
        raise ProvisionError("only HTTPS download URLs are permitted")
    if maximum_bytes <= 0 or timeout_seconds <= 0:
        raise ProvisionError("network budgets must be positive")
    if os.path.lexists(destination):
        raise ProvisionError(f"refusing to overwrite staging artifact: {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    request = Request(url, headers={"User-Agent": "northstar-native-tool-provisioner/1"})
    deadline = time.monotonic() + timeout_seconds
    temporary: str | None = None
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            if time.monotonic() > deadline:
                raise ProvisionError("network response exceeded its time budget")
            _parse_content_length(response.headers, maximum_bytes)
            last_modified = response.headers.get("Last-Modified")
            if require_last_modified and not last_modified:
                raise ProvisionError("offline database response lacks Last-Modified")
            fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.download-", dir=destination.parent)
            digest, total = hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as handle:
                while True:
                    if time.monotonic() > deadline:
                        raise ProvisionError("network response exceeded its time budget")
                    chunk = response.read(CHUNK_BYTES)
                    if time.monotonic() > deadline:
                        raise ProvisionError("network response exceeded its time budget")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum_bytes:
                        raise ProvisionError("network response exceeds its byte budget")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        observed = digest.hexdigest()
        if expected_sha256 is not None and observed != expected_sha256:
            raise ProvisionError("download SHA-256 did not match the pinned value")
        os.chmod(temporary, 0o755 if destination.name == "osv-scanner" else 0o600)
        os.replace(temporary, destination)
        temporary = None
        _fsync_directory(destination.parent)
        return {
            "source": url,
            "sha256": observed,
            "bytes": total,
            "last_modified": last_modified,
            "downloaded_at": utc_now(),
            "byte_budget": maximum_bytes,
            "timeout_seconds": timeout_seconds,
        }
    except Exception:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        raise


def copy_operator_binary(source: str | Path, destination: Path, *, maximum_bytes: int = BWRAP_MAX_BYTES) -> dict:
    """Copy a regular, executable operator-supplied binary without executing it."""
    if os.path.lexists(destination):
        raise ProvisionError(f"refusing to overwrite staging artifact: {destination.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(os.fspath(source), flags)
    except OSError as error:
        raise ProvisionError("bwrap source must be a readable non-symlink file") from error
    temporary: str | None = None
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or not (before.st_mode & 0o111):
            raise ProvisionError("bwrap source must be a regular executable file")
        if before.st_size < 1 or before.st_size > maximum_bytes:
            raise ProvisionError("bwrap source is outside the byte budget")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        out_fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.copy-", dir=destination.parent)
        digest, total = hashlib.sha256(), 0
        with os.fdopen(out_fd, "wb") as output:
            while True:
                chunk = os.read(source_fd, CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise ProvisionError("bwrap source is outside the byte budget")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(source_fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ProvisionError("bwrap source changed while being copied")
        if total != before.st_size:
            raise ProvisionError("bwrap source changed while being copied")
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
        temporary = None
        _fsync_directory(destination.parent)
        return {"sha256": digest.hexdigest(), "bytes": total}
    except Exception:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source_fd)


def isolated_environment(home: Path) -> dict[str, str]:
    """Return the complete child environment; host proxy, token, and pip settings vanish."""
    return {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_NO_INDEX": "1",
        "PIP_ONLY_BINARY": ":all:",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }


def run_command(command: list[str], *, environment: dict[str, str], cwd: Path,
                timeout_seconds: int, capture_stdout: bool = False) -> str:
    """Run only a fixed provisioning command and bound execution time/output."""
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ProvisionError("provisioning subprocess exceeded its time budget") from error
    if completed.returncode != 0:
        raise ProvisionError("provisioning subprocess failed")
    if not capture_stdout:
        return ""
    stdout = completed.stdout or b""
    if not isinstance(stdout, bytes) or len(stdout) > VERSION_OUTPUT_MAX_BYTES:
        raise ProvisionError("Semgrep version output is invalid or outside budget")
    return stdout.decode("utf-8", "strict")


def install_semgrep(stage: Path, wheelhouse: str | Path, python_executable: str,
                    timeout_seconds: int) -> dict:
    """Build an isolated venv from only a complete local binary-wheel wheelhouse."""
    wheelhouse_path = Path(wheelhouse).resolve(strict=True)
    if not wheelhouse_path.is_dir():
        raise ProvisionError("--semgrep-wheelhouse must name a directory")
    empty_cwd = stage / "semgrep-install-cwd"
    empty_home = stage / "semgrep-home"
    empty_cwd.mkdir(mode=0o700)
    empty_home.mkdir(mode=0o700)
    environment = isolated_environment(empty_home)
    venv = stage / "semgrep"
    run_command(
        [python_executable, "-m", "venv", str(venv)],
        environment=environment,
        cwd=empty_cwd,
        timeout_seconds=timeout_seconds,
    )
    venv_python = venv / "bin" / "python"
    semgrep = venv / "bin" / "semgrep"
    # No index is available: pip cannot fetch packages, execute an sdist build,
    # read a project requirement, consume pip.conf, or inherit a credential.
    run_command(
        [
            str(venv_python), "-m", "pip", "install", "--isolated", "--no-index",
            "--find-links", str(wheelhouse_path), "--only-binary=:all:",
            "--no-cache-dir", "--disable-pip-version-check", "--no-input",
            f"semgrep=={SEMGREP_VERSION}",
        ],
        environment=environment,
        cwd=empty_cwd,
        timeout_seconds=timeout_seconds,
    )
    # Deliberately do not use "python -m semgrep": the entry point is verified
    # under the venv interpreter while metrics and the version check remain off.
    version_output = run_command(
        [str(venv_python), str(semgrep), "--version"],
        environment=environment,
        cwd=empty_cwd,
        timeout_seconds=timeout_seconds,
        capture_stdout=True,
    ).strip()
    if re.search(rf"(?<![0-9.]){re.escape(SEMGREP_VERSION)}(?![0-9.])", version_output) is None:
        raise ProvisionError("installed Semgrep did not report the required version")
    return {
        "version": SEMGREP_VERSION,
        "path": "semgrep",
        "version_command": ["semgrep/bin/python", "semgrep/bin/semgrep", "--version"],
        "version_output": version_output,
        "install": {
            "requirement": f"semgrep=={SEMGREP_VERSION}",
            "network": "disabled",
            "only_binary": ":all:",
            "index": "disabled",
            "wheelhouse": str(wheelhouse_path),
        },
    }


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically rename a directory only when destination does not exist (Linux)."""
    if os.path.lexists(destination):
        raise ProvisionError("refusing to overwrite existing output")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ProvisionError("secure publication requires Linux renameat2")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100, os.fsencode(source), -100, os.fsencode(destination), 1  # AT_FDCWD, RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise ProvisionError("refusing to overwrite existing output")
        raise OSError(error, os.strerror(error), os.fspath(destination))


def prepare(output: str | Path, *, bwrap_source: str | Path,
            semgrep_wheelhouse: str | Path, python_executable: str,
            timeout_seconds: int = NETWORK_TIMEOUT_SECONDS) -> dict:
    """Provision all native tool artifacts into a newly published output directory."""
    if not 1 <= timeout_seconds <= NETWORK_TIMEOUT_SECONDS:
        raise ProvisionError(f"timeout must be between 1 and {NETWORK_TIMEOUT_SECONDS} seconds")
    requested = Path(output).expanduser()
    parent = requested.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ProvisionError("output parent must be a directory")
    target = parent / requested.name
    if target.name in {"", ".", ".."} or os.path.lexists(target):
        raise ProvisionError("refusing to overwrite existing output")
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
    try:
        (stage / "osv").mkdir(mode=0o700)
        osv_binary = download_to_file(
            OSV_LINUX_AMD64_URL,
            stage / "osv" / "osv-scanner",
            expected_sha256=OSV_LINUX_AMD64_SHA256,
            maximum_bytes=OSV_BINARY_MAX_BYTES,
            timeout_seconds=timeout_seconds,
        )
        bwrap = copy_operator_binary(bwrap_source, stage / "bwrap" / "bwrap")
        semgrep = install_semgrep(stage, semgrep_wheelhouse, python_executable, timeout_seconds)
        database = download_to_file(
            OSV_PYPI_ALL_URL,
            stage / "database" / "osv-scanner" / "PyPI" / "all.zip",
            expected_sha256=None,
            maximum_bytes=OSV_DATABASE_MAX_BYTES,
            timeout_seconds=timeout_seconds,
            require_last_modified=True,
        )
        manifest = {
            "schema": SCHEMA,
            "prepared_at": utc_now(),
            "network_budgets": {
                "timeout_seconds": timeout_seconds,
                "osv_binary_max_bytes": OSV_BINARY_MAX_BYTES,
                "osv_database_max_bytes": OSV_DATABASE_MAX_BYTES,
            },
            "tools": {
                "osv-scanner": {
                    "version": OSV_VERSION,
                    "path": "osv",
                    "binary": {
                        **osv_binary,
                        "expected_sha256": OSV_LINUX_AMD64_SHA256,
                        "integrity": "pinned SHA-256 match; not a publisher signature",
                    },
                },
                "semgrep": semgrep,
                "bwrap": {
                    "path": "bwrap/bwrap",
                    "source": "operator-supplied --bwrap-source (not executed)",
                    **bwrap,
                },
            },
            "database": {
                "source": database["source"],
                "path": "database/osv-scanner/PyPI/all.zip",
                "last_modified": database["last_modified"],
                "sha256": database["sha256"],
                "bytes": database["bytes"],
                "downloaded_at": database["downloaded_at"],
                "signature_verified": False,
                "download_during_scan": False,
                "byte_budget": database["byte_budget"],
                "timeout_seconds": database["timeout_seconds"],
            },
            "limitations": [
                "Semgrep binary-only installation from a wheelhouse is not a complete hash lock or author-provenance verification.",
                "The OSV database SHA-256 is an observation, not a publisher signature.",
                "Production use requires an approved immutable image and separately reviewed tool roots.",
            ],
        }
        _atomic_write(stage / "tool-provisioning.json", json.dumps(
            manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n")
        _fsync_directory(stage)
        _rename_noreplace(stage, target)
        _fsync_directory(parent)
        return {"schema": SCHEMA, "exit_code": 0, "output": str(target)}
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare pinned native scanner tools; never scan, sign, or install system packages."
    )
    parser.add_argument("--output", required=True, help="new directory to publish atomically")
    parser.add_argument("--bwrap-source", required=True, help="trusted, pre-provided bwrap executable to copy")
    parser.add_argument(
        "--semgrep-wheelhouse", required=True,
        help="complete local wheelhouse containing only approved binary wheels; pip networking remains disabled",
    )
    parser.add_argument("--python", default=sys.executable, help="Python used only to create the isolated Semgrep venv")
    parser.add_argument("--timeout-seconds", type=int, default=NETWORK_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = prepare(
            args.output,
            bwrap_source=args.bwrap_source,
            semgrep_wheelhouse=args.semgrep_wheelhouse,
            python_executable=args.python,
            timeout_seconds=args.timeout_seconds,
        )
    except Exception as error:
        result = {"schema": SCHEMA, "exit_code": 2, "error": type(error).__name__}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
