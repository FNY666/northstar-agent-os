"""Canonical, bounded host sets for host-owned per-run egress scope."""
from __future__ import annotations

import re
from typing import Any, Sequence

MAX_EGRESS_SCOPE_HOSTS = 128
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def canonical_egress_host(value: Any) -> str | None:
    """Return an exact ASCII DNS-style host key, or ``None`` for invalid input."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        return None
    if any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
        return None
    return host


def validate_egress_target_scope(values: Any, *, field_name: str = "egress_target_scope") -> tuple[str, ...]:
    """Validate and canonicalize a bounded sequence; empty means deny all hosts."""
    if not isinstance(values, (tuple, list)):
        raise ValueError(f"{field_name} must be a sequence of exact hostnames")
    if len(values) > MAX_EGRESS_SCOPE_HOSTS:
        raise ValueError(f"{field_name} may contain at most {MAX_EGRESS_SCOPE_HOSTS} hostnames")
    canonical: list[str] = []
    for target in values:
        host = canonical_egress_host(target)
        if host is None:
            raise ValueError(f"{field_name} contains an invalid exact hostname: {target!r}")
        if host in canonical:
            raise ValueError(f"{field_name} contains a duplicate hostname: {target!r}")
        canonical.append(host)
    return tuple(canonical)


def intersect_egress_target_scopes(
    cli_targets: Sequence[str],
    policy_targets: Sequence[str] | None,
) -> tuple[str, ...] | None:
    """Combine operator CLI scope with policy scope without widening either."""
    cli_scope = validate_egress_target_scope(tuple(cli_targets), field_name="--egress-target")
    if policy_targets is None:
        return cli_scope or None
    policy_scope = validate_egress_target_scope(tuple(policy_targets), field_name="policy egress_targets")
    if not cli_scope:
        return policy_scope
    policy_set = set(policy_scope)
    return tuple(host for host in cli_scope if host in policy_set)


__all__ = [
    "MAX_EGRESS_SCOPE_HOSTS",
    "canonical_egress_host",
    "validate_egress_target_scope",
    "intersect_egress_target_scopes",
]
