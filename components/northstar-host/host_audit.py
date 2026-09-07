"""Bridge host authorization decisions into the canonical NDJSON audit feed.

The host depends on ``northstar-run-contract``, so the envelope definition
lives there (``audit.py``) and this module only maps the *verified* grant
dict (the unsigned claims that ``verify_authorization`` returns inside
``AuthorizationValidation.authorization``) into audit records. Only verified
grants are exported - a tampered token is reported as an error by the caller,
never as an audit record here.
"""
from __future__ import annotations

from typing import Any

from audit import new_record

COMPONENT = "northstar-host"

_PAYLOAD_KEYS = (
    "schema_version",
    "workspace_id",
    "capabilities",
    "policy_revision",
    "expires_at",
)


def authorization_to_audit(
    authorization: dict[str, Any],
    *,
    ts: str | None = None,
    level: str = "info",
) -> dict[str, Any]:
    """Map one verified authorization grant dict to a canonical audit record.

    ``expires_at`` is epoch seconds and stays numeric inside ``payload`` (the
    audit ts is *when the decision happened*, which the host does not record -
    pass ``ts`` explicitly when the caller knows it).
    """
    payload = {key: authorization[key] for key in _PAYLOAD_KEYS if key in authorization}
    return new_record(
        COMPONENT,
        "authorization_grant",
        ts=ts,
        level=level,
        payload=payload,
        actor_id=authorization.get("actor_id"),
        run_id=authorization.get("run_id"),
    )


def authorization_to_ndjson(authorization: dict[str, Any]) -> str:
    """One signed-grant claim dict as a single canonical audit NDJSON line."""
    from audit import dumps_record

    return dumps_record(authorization_to_audit(authorization)) + "\n"
