"""Independent postcondition verification for the durable-run slice."""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from durable_contract import RunContract
from event_store import EventStore

_PRIVATE_MODE = 0o700
_DIGEST_PREFIX = "sha256:"


@dataclass(frozen=True)
class VerificationResult:
    verdict: str
    errors: tuple[str, ...]
    artifact_digests: dict[str, str]

    def __post_init__(self) -> None:
        if self.verdict not in {"verified", "failed", "unknown"}:
            raise ValueError("verification verdict is invalid")
        if not isinstance(self.errors, tuple):
            raise ValueError("verification errors must be a tuple")
        if not isinstance(self.artifact_digests, dict):
            raise ValueError("artifact_digests must be an object")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ValueError("artifact could not be read") from error
    return _DIGEST_PREFIX + digest.hexdigest()


def _private_workspace(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError("workspace could not be inspected") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("workspace must be a private directory")
    if stat.S_IMODE(info.st_mode) != _PRIVATE_MODE:
        raise ValueError("workspace must have mode 0700")


def _private_parent_chain(workspace: Path, relative: Path) -> None:
    current = workspace
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ValueError("required artifact parent is missing") from error
        except OSError as error:
            raise ValueError("required artifact parent could not be inspected") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("required artifact parent is a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("required artifact parent is not a directory")


def _safe_relative_path(name: Any) -> Path:
    if not isinstance(name, str) or not name or name.startswith("/"):
        raise ValueError("required file path must be relative")
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ValueError("required file path must not escape workspace")
    return candidate


def verify_run_completion(
    run: RunContract,
    store: EventStore,
    *,
    workspace: str | Path,
    required_files: dict[str, str],
    test_exit_code: int | None,
    now: int,
    claimed_status: str | None = None,
) -> VerificationResult:
    """Verify real local postconditions; never trust a model status claim."""
    if not isinstance(run, RunContract):
        raise ValueError("run must be a RunContract")
    if not isinstance(store, EventStore):
        raise ValueError("store must be an EventStore")
    if not isinstance(required_files, dict):
        raise ValueError("required_files must be an object")
    if not isinstance(now, int) or isinstance(now, bool):
        raise ValueError("now must be an integer")
    if now >= run.deadline_at:
        return VerificationResult("unknown", ("run deadline has expired",), {})
    if claimed_status is not None and not isinstance(claimed_status, str):
        raise ValueError("claimed_status must be a string")

    try:
        state = store.derive_state(run.run_id)
    except ValueError as error:
        return VerificationResult("unknown", (f"event history unavailable: {error}",), {})
    if state["status"] != "finished":
        if state["status"] == "cancelled":
            return VerificationResult("failed", ("run was cancelled",), {})
        return VerificationResult(
            "unknown", (f"run is not finished: {state['status']}",), {}
        )

    if test_exit_code is None:
        return VerificationResult("unknown", ("test exit code was not observed",), {})
    if not isinstance(test_exit_code, int) or isinstance(test_exit_code, bool):
        raise ValueError("test_exit_code must be an integer or None")
    errors: list[str] = []
    if test_exit_code != 0:
        errors.append(f"test command exit code was {test_exit_code}")

    workspace_path = Path(workspace).absolute()
    try:
        _private_workspace(workspace_path)
    except ValueError as error:
        return VerificationResult("failed", (str(error),), {})

    artifacts: dict[str, str] = {}
    for name, expected in required_files.items():
        try:
            relative = _safe_relative_path(name)
        except ValueError as error:
            errors.append(str(error))
            continue
        if not isinstance(expected, str) or not expected.startswith(_DIGEST_PREFIX):
            errors.append(f"expected digest is invalid for {name}")
            continue
        path = workspace_path / relative
        try:
            _private_parent_chain(workspace_path, relative)
        except ValueError as error:
            errors.append(f"{name}: {error}")
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            errors.append(f"required artifact is missing: {name}")
            continue
        except OSError:
            errors.append(f"required artifact could not be inspected: {name}")
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(f"required artifact is a symlink: {name}")
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(f"required artifact is not a regular file: {name}")
            continue
        try:
            actual = _file_digest(path)
        except ValueError as error:
            errors.append(f"{name}: {error}")
            continue
        artifacts[name] = actual
        if actual != expected:
            errors.append(f"artifact digest mismatch: {name}")

    if errors:
        return VerificationResult("failed", tuple(errors), artifacts)
    return VerificationResult("verified", (), artifacts)


def make_final_receipt(
    run: RunContract, result: VerificationResult
) -> dict[str, Any]:
    if not isinstance(run, RunContract):
        raise ValueError("run must be a RunContract")
    if not isinstance(result, VerificationResult):
        raise ValueError("result must be a VerificationResult")
    if result.verdict == "verified":
        if result.errors:
            raise ValueError("verified result cannot contain errors")
        status = "ok"
    elif result.verdict == "failed":
        status = "failed"
    else:
        status = "unknown"
    return {
        "schema_version": "northstar.durable-receipt.v1",
        "run_id": run.run_id,
        "status": status,
        "verification": result.verdict,
        "errors": list(result.errors),
        "artifacts": dict(result.artifact_digests),
    }
