"""Host-side opaque workspace allocation for authorized Northstar runs."""
from __future__ import annotations

import hashlib
import hmac
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authorization import verify_authorization
from binding import verify_binding
from contract import _valid_id, validate_run_request

_PRIVATE_MODE = 0o700


@dataclass(frozen=True)
class WorkspaceAllocation:
    workspace_key: str
    path: Path


def _require_secret(secret: bytes, name: str) -> None:
    if not isinstance(secret, bytes) or not secret:
        raise ValueError(f"{name} must be non-empty bytes")


def _require_revision(value: Any) -> None:
    errors = _valid_id(value, "policy revision")
    if errors:
        raise ValueError(errors[0])


def _canonical_claims(run: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "actor_id": run["actor_id"],
            "run_id": run["run_id"],
            "workspace_id": run["workspace_id"],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _derive_workspace_key(run: dict[str, Any], secret: bytes) -> str:
    return hmac.new(secret, _canonical_claims(run), hashlib.sha256).hexdigest()


def _private_directory(path: Path, *, create: bool) -> None:
    """Require one exact private directory, never following a symlink."""
    try:
        current = path.lstat()
    except FileNotFoundError:
        if not create:
            raise ValueError("workspace directory does not exist")
        try:
            path.mkdir(mode=_PRIVATE_MODE)
        except (FileExistsError, OSError) as error:
            raise ValueError("workspace directory could not be created") from error
        try:
            current = path.lstat()
        except OSError as error:
            raise ValueError("workspace directory could not be inspected") from error

    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise ValueError("workspace path must be a directory, not a symlink or file")
    if stat.S_IMODE(current.st_mode) != _PRIVATE_MODE:
        raise ValueError("workspace directory must have mode 0700")


class WorkspaceBroker:
    """Re-verify host grants and allocate one opaque private run directory."""

    def __init__(
        self,
        root: str | Path,
        *,
        binding_secret: bytes,
        authorization_secret: bytes,
        derivation_secret: bytes,
    ) -> None:
        _require_secret(binding_secret, "binding_secret")
        _require_secret(authorization_secret, "authorization_secret")
        _require_secret(derivation_secret, "derivation_secret")
        self._root = Path(root).absolute()
        self._binding_secret = binding_secret
        self._authorization_secret = authorization_secret
        self._derivation_secret = derivation_secret

    def allocate(
        self,
        run: dict[str, Any],
        binding_token: str,
        authorization_token: str,
        *,
        current_policy_revision: str,
        now: int,
    ) -> WorkspaceAllocation:
        validation = validate_run_request(run)
        if not validation.ok:
            raise ValueError(validation.errors[0])
        if not isinstance(now, int) or isinstance(now, bool):
            raise ValueError("now must be an integer")
        _require_revision(current_policy_revision)

        binding = verify_binding(binding_token, self._binding_secret, now=now)
        if not binding.ok or binding.binding is None:
            raise ValueError("run binding is not valid")
        authorization = verify_authorization(
            authorization_token, self._authorization_secret, now=now
        )
        if not authorization.ok or authorization.authorization is None:
            raise ValueError("authorization grant is not valid")
        binding_claims = binding.binding
        grant = authorization.authorization

        for field in ("run_id", "actor_id", "workspace_id"):
            if binding_claims.get(field) != run[field]:
                raise ValueError(f"binding does not match run {field}")
            if grant.get(field) != run[field]:
                raise ValueError(f"authorization does not match run {field}")
        if grant.get("policy_revision") != current_policy_revision:
            raise ValueError("authorization policy revision is stale")
        if set(grant.get("capabilities", [])) != set(
            run["requested_capabilities"]
        ):
            raise ValueError("authorization capabilities do not match run")

        workspace_key = _derive_workspace_key(run, self._derivation_secret)
        root = self._root
        runs = root / "runs"
        workspace = runs / workspace_key
        _private_directory(root, create=True)
        _private_directory(runs, create=True)
        _private_directory(workspace, create=True)
        return WorkspaceAllocation(workspace_key=workspace_key, path=workspace)
