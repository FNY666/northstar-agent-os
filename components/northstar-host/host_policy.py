"""Policy as code for the host: load ``northstar-policy.toml`` documents.

The host's authorization boundary needs an explicit policy — who may request
which capabilities under which revision. ``authorization.HostPolicy`` is the
in-memory shape; this module loads it from a versioned, reviewable TOML
document (``northstar-policy.toml``), so policy lives in the repository like
code and its revision id flows into every signed authorization grant and
audit record.

Document shape (``schema_version`` optional, defaults to v1; ``revision``
required; ``actors`` optional, defaults to deny-all):

.. code-block:: toml

    schema_version = "northstar.policy.v1"
    revision = "2026-09-07.r1"        # audit correlation key, <= 128 chars

    [actors]
    "actor-001" = ["research", "search"]
    "actor-002" = []                  # listed but holding no capability = deny-all

Validation is delegated to the run contract's canonical policy identity
(``policy.py``) and to ``HostPolicy.from_mapping``, which applies the same
strict id/capability rules as ``authorize_run`` — a document that would not
parse as a policy is refused here, at load time.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as _toml  # type: ignore[no-redef]
    except ImportError as error:  # pragma: no cover - depends on the host
        raise ImportError(
            "reading northstar-policy.toml needs Python 3.11+ or the 'tomli' package "
            "(pip install tomli)"
        ) from error

from authorization import HostPolicy
from policy import POLICY_SCHEMA_VERSION, require_supported_schema, validate_revision

POLICY_FILE_NAME = "northstar-policy.toml"
_ALLOWED_KEYS = frozenset({"schema_version", "revision", "actors"})


def policy_file_path(directory: str | Path) -> Path:
    return Path(directory) / POLICY_FILE_NAME


def load_host_policy(directory: str | Path) -> HostPolicy:
    """Load and validate ``northstar-policy.toml`` under ``directory``.

    The file must exist and parse as one policy document; anything else raises
    ``ValueError`` naming the path — the host treats policy as required, and a
    missing or unreadable policy must fail closed at the boundary.
    """
    path = policy_file_path(directory)
    if not path.is_file():
        raise ValueError(f"{path}: policy file not found (host policy is required)")
    try:
        raw = _toml.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"{path}: cannot read policy file: {error}") from error
    except Exception as error:  # tomllib.TOMLDecodeError / tomli
        raise ValueError(f"{path}: invalid TOML: {error}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: the policy file must be a TOML table")

    def fail(message: str) -> None:
        raise ValueError(f"{path}: {message}")

    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        fail(f"unknown key(s) {', '.join(unknown)} - allowed: {', '.join(sorted(_ALLOWED_KEYS))}")

    require_supported_schema(
        raw.get("schema_version", POLICY_SCHEMA_VERSION),
        context=str(path),
    )
    revision = raw.get("revision")
    if revision is None:
        fail("revision is required (the revision id flows into authorization grants and audit records)")
    errors = validate_revision(revision)
    if errors:
        fail(errors[0])

    actors = raw.get("actors", {})
    if not isinstance(actors, dict):
        fail("'actors' must be a table mapping actor ids to arrays of capabilities")
    normalized: dict[str, Any] = {}
    for actor_id, capabilities in actors.items():
        if isinstance(capabilities, (str, bytes, bytearray)):
            fail(f"actors[{actor_id!r}] must be an array of capability names")
        normalized[actor_id] = capabilities

    try:
        return HostPolicy.from_mapping(revision, normalized)
    except ValueError as error:
        raise ValueError(f"{path}: {error}") from error
