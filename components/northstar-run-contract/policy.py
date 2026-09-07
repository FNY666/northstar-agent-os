"""Canonical policy-document identity: schema version + revision rules.

Every Northstar policy document — the runtime's ``.northstar/config.toml``
and the host's ``northstar-policy.toml`` — speaks one versioned schema
(``northstar.policy.v1``) and may carry a human/CI-assigned revision id that
flows into signed authorization grants and the audit feed, so a decision can
always be traced back to the exact policy revision that governed it.

The runtime mirrors the schema-version string locally (it is deliberately
dependency-free); both sides pin the same value in tests. This module is the
validating implementation for components that may depend on the run contract
(the host).
"""
from __future__ import annotations

import re
from typing import Any

POLICY_SCHEMA_VERSION = "northstar.policy.v1"
SUPPORTED_POLICY_SCHEMA_VERSIONS: tuple[str, ...] = (POLICY_SCHEMA_VERSION,)
MAX_REVISION_CHARS = 128
_REVISION_RE = re.compile(r"^[^\s/\\]+$")


def validate_schema_version(value: Any) -> tuple[str, ...]:
    """Envelope schema errors; empty tuple when the version is supported."""
    if value is None:
        return ()
    if not isinstance(value, str):
        return (f"policy schema_version must be a string, got {type(value).__name__}",)
    if value not in SUPPORTED_POLICY_SCHEMA_VERSIONS:
        supported = ", ".join(SUPPORTED_POLICY_SCHEMA_VERSIONS)
        return (f"unsupported policy schema_version {value!r} - supported: {supported}",)
    return ()


def validate_revision(value: Any) -> tuple[str, ...]:
    """Revision-id errors; empty tuple when valid.

    The rules mirror the contract's id rule (``_valid_id``): non-empty, at
    most 128 characters, no whitespace and no ``/`` or ``\\``. Revisions are
    meant to be file names and audit correlation keys, so free text is not
    accepted.
    """
    if value is None:
        return ()
    if not isinstance(value, str):
        return ("policy revision must be a string",)
    if not value:
        return ("policy revision must be a non-empty string",)
    if len(value) > MAX_REVISION_CHARS:
        return ("policy revision is too long",)
    if not _REVISION_RE.fullmatch(value):
        return ("policy revision must not contain whitespace, /, or \\",)
    return ()


def require_supported_schema(value: Any, *, context: str) -> None:
    """Raise ``ValueError`` (with ``context`` in the message) when unsupported."""
    errors = validate_schema_version(value)
    if errors:
        raise ValueError(f"{context}: {errors[0]}")
