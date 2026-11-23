"""Resource tagging — AWS Tag Editor-shaped tag bookkeeping (thirty-fourth batch).

Research note (tag literature): AWS Tag Editor / Resource Groups Tagging
API treat tags as ``(key, value)`` string pairs attached to resources;
keys are 1-128 chars, values 0-256 chars, the ``aws:`` prefix is
reserved, and tag policies (via AWS Organizations) declare *required
tags* plus per-key *allowed values* with an enforcement verdict that is
data, never an exception. This module takes the single-host
deterministic intersection:

* **Resources**: ``register`` books a resource id + namespaced type.
  Tag keys follow the AWS charset and length bounds; the ``aws:``
  prefix is refused (reserved).
* **Tag/untag**: ``tag`` upserts ``(key, value)`` pairs (latest wins),
  minting a frozen ``TagApplication``; ``untag`` removes keys, minting
  a frozen ``UntagRecord``. Removing a key that is not set is refused
  fail-closed (a silent no-op removal would lie about the change).
* **Policies**: ``policy`` declares required keys and per-key allowed
  value lists; ``evaluate`` returns compliance as *data* — violations
  are ``missing`` or ``disallowed-value`` entries, never raised.
  Evaluation is an audited read: the seq is validated but not consumed.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *tag decisions* deterministically.
It cannot observe the cloud control plane, enforce tags on actual
resources, or prove a declared policy matches what a provider sees —
a consumer wires the frozen records to its real tagging API. Tag
*values* never cross the audit boundary (keys may carry meaning, values
may carry identities); records pin values only as ``sha256:`` digests
in the audit detail. GIGO on resource ids: the ledger pins what the
host declares.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

#: Version pin for this module's record shape.
RESOURCE_TAGGING_VERSION = "resource-tagging.v1"

#: Schema pin carried by records and audit events.
RESOURCE_TAGGING_SCHEMA = "northstar.resource-tagging.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Reserved tag-key prefix (AWS reserves ``aws:`` case-insensitively).
_RESERVED_PREFIX = "aws:"

#: Tag charset (AWS-shaped). Keys 1..128 chars, values 0..256 chars.
_TAG_CHARSET = re.compile(r"^[A-Za-z0-9 _.:/=+\-@]*$")
_MAX_KEY_LEN = 128
_MAX_VALUE_LEN = 256

#: Resource id bounds.
_MAX_RESOURCE_ID_LEN = 512

#: Audit event kinds.
KIND_RESOURCE_REGISTERED = "tagging.resource-registered"
KIND_TAGS_APPLIED = "tagging.tags-applied"
KIND_TAGS_REMOVED = "tagging.tags-removed"
KIND_POLICY_DEFINED = "tagging.policy-defined"
KIND_POLICY_EVALUATED = "tagging.policy-evaluated"
KIND_REJECTED = "tagging.rejected"
_KINDS = (
    KIND_RESOURCE_REGISTERED,
    KIND_TAGS_APPLIED,
    KIND_TAGS_REMOVED,
    KIND_POLICY_DEFINED,
    KIND_POLICY_EVALUATED,
    KIND_REJECTED,
)

_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ResourceTaggingError(ValueError):
    """Base error for the resource tagging manager."""


class BadResourceError(ResourceTaggingError):
    """Malformed resource id or resource type."""


class DuplicateResourceError(ResourceTaggingError):
    """This resource id is already registered."""


class UnknownResourceError(ResourceTaggingError):
    """No resource with this id is registered."""


class BadTagError(ResourceTaggingError):
    """Malformed tag key or value."""


class BadPolicyError(ResourceTaggingError):
    """Malformed tag policy."""


class DuplicatePolicyError(ResourceTaggingError):
    """This policy id is already defined."""


class UnknownPolicyError(ResourceTaggingError):
    """No policy with this id is defined."""


class SeqOrderError(ResourceTaggingError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ResourceTaggingError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadResourceError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_RESOURCE_ID_LEN:
        raise BadResourceError(f"{field_name} exceeds {_MAX_RESOURCE_ID_LEN} chars")
    if any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise BadResourceError(f"{field_name} must not contain whitespace/control chars")
    return value


def _check_resource_type(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadResourceError("resource_type must be a non-empty string")
    value = value.strip()
    if len(value) > _MAX_KEY_LEN:
        raise BadResourceError("resource_type exceeds 128 chars")
    if ":" not in value:
        raise BadResourceError(
            "resource_type must be namespaced (e.g. 'ec2:instance')"
        )
    if not _TAG_CHARSET.match(value) or value != value.lower():
        raise BadResourceError(
            "resource_type must be lowercase and match the tag charset"
        )
    return value


def _check_tag_key(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise BadTagError("tag key must be a non-empty string")
    if len(value) > _MAX_KEY_LEN:
        raise BadTagError(f"tag key exceeds {_MAX_KEY_LEN} chars")
    if not _TAG_CHARSET.match(value):
        raise BadTagError(f"tag key has illegal characters: {value!r}")
    if value.lower().startswith(_RESERVED_PREFIX):
        raise BadTagError(f"tag key prefix 'aws:' is reserved: {value!r}")
    return value


def _check_tag_value(value: Any) -> str:
    if not isinstance(value, str):
        raise BadTagError("tag value must be a string")
    if len(value) > _MAX_VALUE_LEN:
        raise BadTagError(f"tag value exceeds {_MAX_VALUE_LEN} chars")
    if value and not _TAG_CHARSET.match(value):
        raise BadTagError(f"tag value has illegal characters: {value!r}")
    return value


def _check_tags(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise BadTagError("tags must be a mapping")
    if not value:
        raise BadTagError("tags must not be empty")
    pairs = tuple(
        (_check_tag_key(k), _check_tag_value(v)) for k, v in value.items()
    )
    if len({k for k, _ in pairs}) != len(pairs):
        raise BadTagError("duplicate tag keys")
    return pairs


def _check_keys(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not value:
        raise BadTagError("keys must be a non-empty tuple/list")
    keys = tuple(_check_tag_key(k) for k in value)
    if len(set(keys)) != len(keys):
        raise BadTagError("duplicate keys")
    return keys


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list/tuple only — no floats,
    # so no >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(parts)).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceRecord:
    """One registered resource (frozen)."""

    resource_id: str
    resource_type: str
    registered_seq: int
    digest: str = field(default="")
    schema: str = RESOURCE_TAGGING_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _pin(
            RESOURCE_TAGGING_VERSION,
            "resource",
            self.resource_id,
            self.resource_type,
            self.registered_seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class TagApplication:
    """One tag upsert applied to a resource (frozen).

    ``tags`` is the sorted ``(key, value)`` tuple that was applied;
    the module keeps the merged view separately.
    """

    resource_id: str
    tags: tuple[tuple[str, str], ...]
    seq: int
    digest: str = field(default="")
    schema: str = RESOURCE_TAGGING_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _pin(
            RESOURCE_TAGGING_VERSION,
            "tag",
            self.resource_id,
            self.tags,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class UntagRecord:
    """One tag-key removal from a resource (frozen)."""

    resource_id: str
    keys: tuple[str, ...]
    seq: int
    digest: str = field(default="")
    schema: str = RESOURCE_TAGGING_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _pin(
            RESOURCE_TAGGING_VERSION,
            "untag",
            self.resource_id,
            self.keys,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class PolicyRecord:
    """One tag policy (frozen).

    ``required`` lists keys every governed resource must carry;
    ``allowed_values`` maps a key to its pinned allowed-value tuple
    (keys not listed have no value constraint).
    """

    policy_id: str
    required: tuple[str, ...]
    allowed_values: tuple[tuple[str, tuple[str, ...]], ...]
    seq: int
    digest: str = field(default="")
    schema: str = RESOURCE_TAGGING_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _pin(
            RESOURCE_TAGGING_VERSION,
            "policy",
            self.policy_id,
            self.required,
            self.allowed_values,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class PolicyEvaluation:
    """One policy evaluation against a resource (frozen).

    ``compliant`` and ``violations`` are data, never raised. A
    violation is a ``(key, reason)`` pair where reason is ``missing``
    or ``disallowed-value``.
    """

    policy_id: str
    resource_id: str
    compliant: bool
    violations: tuple[tuple[str, str], ...]
    seq: int
    digest: str = field(default="")
    schema: str = RESOURCE_TAGGING_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _pin(
            RESOURCE_TAGGING_VERSION,
            "evaluate",
            self.policy_id,
            self.resource_id,
            self.compliant,
            self.violations,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


def resource_tagging_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for resource tagging.

    Detail carries ids + digest pins only — tag *values* never cross
    the audit boundary.
    """
    if kind not in _KINDS:
        raise ResourceTaggingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    for banned in ("value", "values", "tags"):
        if banned in detail:
            raise ResourceTaggingError(
                f"detail carries banned key: {banned!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "resource_tagging",
        "module_version": RESOURCE_TAGGING_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# ResourceTagging
# ---------------------------------------------------------------------------


class ResourceTagging:
    """Deterministic AWS-Tag-Editor-shaped tag bookkeeping.

    Resources are registered with a namespaced type; ``tag`` upserts
    ``(key, value)`` pairs, ``untag`` removes keys, ``policy`` defines
    required tags and per-key allowed values, and ``evaluate`` returns
    compliance as data. Mutation seqs must be strictly increasing;
    failed mutations consume their seq (batch-21 ledger discipline).
    No wall-clock, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._resources: dict[str, ResourceRecord] = {}
        self._tags: dict[str, dict[str, str]] = {}
        self._policies: dict[str, PolicyRecord] = {}
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq

    def _peek_seq(self, seq: int) -> None:
        # Reads validate seq shape but never consume it.
        _check_seq(seq, "seq")

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(resource_tagging_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    def _require_resource(self, resource_id: str) -> None:
        if resource_id not in self._resources:
            raise UnknownResourceError(f"unknown resource: {resource_id!r}")

    # -- mutations --------------------------------------------------------

    def register(
        self, resource_id: str, resource_type: str, seq: int
    ) -> ResourceRecord:
        """Register a resource with a namespaced type."""
        with self._lock:
            self._claim_seq(seq)
            resource_id = _check_id(resource_id, "resource_id")
            resource_type = _check_resource_type(resource_type)
            if resource_id in self._resources:
                self._reject(seq, resource_id=resource_id)
                raise DuplicateResourceError(
                    f"resource already registered: {resource_id!r}"
                )
            record = ResourceRecord(
                resource_id=resource_id,
                resource_type=resource_type,
                registered_seq=seq,
            )
            self._resources[resource_id] = record
            self._tags[resource_id] = {}
            self._emit(
                KIND_RESOURCE_REGISTERED,
                seq,
                resource_id=resource_id,
                resource_digest=record.digest,
            )
            return record

    def tag(
        self, resource_id: str, tags: Mapping[str, str], seq: int
    ) -> TagApplication:
        """Upsert ``(key, value)`` pairs onto a resource (latest wins)."""
        with self._lock:
            self._claim_seq(seq)
            resource_id = _check_id(resource_id, "resource_id")
            pairs = _check_tags(tags)
            self._require_resource(resource_id)
            current = self._tags[resource_id]
            for key, value in pairs:
                current[key] = value
            record = TagApplication(
                resource_id=resource_id,
                tags=tuple(sorted(pairs)),
                seq=seq,
            )
            self._emit(
                KIND_TAGS_APPLIED,
                seq,
                resource_id=resource_id,
                keys=tuple(sorted(k for k, _ in pairs)),
                tag_digest=record.digest,
            )
            return record

    def untag(
        self, resource_id: str, keys: Sequence[str], seq: int
    ) -> UntagRecord:
        """Remove tag keys from a resource.

        Every key must currently be set: removing a key that is not
        set is refused fail-closed (a silent no-op would lie about the
        change).
        """
        with self._lock:
            self._claim_seq(seq)
            resource_id = _check_id(resource_id, "resource_id")
            keys = _check_keys(keys)
            self._require_resource(resource_id)
            current = self._tags[resource_id]
            missing = [k for k in keys if k not in current]
            if missing:
                self._reject(seq, resource_id=resource_id, keys=tuple(missing))
                raise BadTagError(
                    f"keys not set on {resource_id!r}: {missing!r}"
                )
            for key in keys:
                del current[key]
            record = UntagRecord(resource_id=resource_id, keys=keys, seq=seq)
            self._emit(
                KIND_TAGS_REMOVED,
                seq,
                resource_id=resource_id,
                keys=keys,
                untag_digest=record.digest,
            )
            return record

    def policy(
        self,
        policy_id: str,
        required_tags: Sequence[str],
        seq: int,
        allowed_values: Mapping[str, Sequence[str]] | None = None,
    ) -> PolicyRecord:
        """Define a tag policy: required keys + per-key allowed values."""
        with self._lock:
            self._claim_seq(seq)
            policy_id = _check_id(policy_id, "policy_id")
            if not isinstance(required_tags, (tuple, list)) or not required_tags:
                raise BadPolicyError(
                    "required_tags must be a non-empty tuple/list"
                )
            required = tuple(_check_tag_key(k) for k in required_tags)
            if len(set(required)) != len(required):
                raise BadPolicyError("duplicate required tags")
            constrained: list[tuple[str, tuple[str, ...]]] = []
            if allowed_values is not None:
                if not isinstance(allowed_values, Mapping):
                    raise BadPolicyError("allowed_values must be a mapping")
                for key, values in allowed_values.items():
                    _check_tag_key(key)
                    if not isinstance(values, (tuple, list)) or not values:
                        raise BadPolicyError(
                            f"allowed values for {key!r} must be non-empty"
                        )
                    checked = tuple(_check_tag_value(v) for v in values)
                    if len(set(checked)) != len(checked):
                        raise BadPolicyError(
                            f"duplicate allowed values for {key!r}"
                        )
                    constrained.append((key, checked))
                constrained.sort()
            if policy_id in self._policies:
                self._reject(seq, policy_id=policy_id)
                raise DuplicatePolicyError(
                    f"policy already defined: {policy_id!r}"
                )
            record = PolicyRecord(
                policy_id=policy_id,
                required=required,
                allowed_values=tuple(constrained),
                seq=seq,
            )
            self._policies[policy_id] = record
            self._emit(
                KIND_POLICY_DEFINED,
                seq,
                policy_id=policy_id,
                policy_digest=record.digest,
            )
            return record

    # -- reads ------------------------------------------------------------

    def evaluate(
        self, policy_id: str, resource_id: str, seq: int
    ) -> PolicyEvaluation:
        """Evaluate a policy against a resource's current tags.

        Compliance is data, never raised. Audited read: the seq is
        validated but not consumed.
        """
        with self._lock:
            self._peek_seq(seq)
            policy_id = _check_id(policy_id, "policy_id")
            resource_id = _check_id(resource_id, "resource_id")
            policy = self._policies.get(policy_id)
            if policy is None:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            self._require_resource(resource_id)
            current = self._tags[resource_id]
            allowed = dict(policy.allowed_values)
            violations: list[tuple[str, str]] = []
            for key in policy.required:
                if key not in current:
                    violations.append((key, "missing"))
                elif key in allowed and current[key] not in allowed[key]:
                    violations.append((key, "disallowed-value"))
            for key, values in allowed.items():
                if key in current and key not in policy.required:
                    if current[key] not in values:
                        violations.append((key, "disallowed-value"))
            violations = sorted(set(violations))
            record = PolicyEvaluation(
                policy_id=policy_id,
                resource_id=resource_id,
                compliant=not violations,
                violations=tuple(violations),
                seq=seq,
            )
            self._emit(
                KIND_POLICY_EVALUATED,
                seq,
                policy_id=policy_id,
                resource_id=resource_id,
                compliant=record.compliant,
                evaluation_digest=record.digest,
            )
            return record

    def tags(self, resource_id: str) -> Mapping[str, str]:
        """Current tags for a resource (pure read)."""
        with self._lock:
            resource_id = _check_id(resource_id, "resource_id")
            self._require_resource(resource_id)
            return dict(self._tags[resource_id])

    def resource(self, resource_id: str) -> ResourceRecord:
        """Frozen record for a registered resource."""
        with self._lock:
            resource_id = _check_id(resource_id, "resource_id")
            self._require_resource(resource_id)
            return self._resources[resource_id]

    def policy_record(self, policy_id: str) -> PolicyRecord:
        """Frozen record for a defined policy."""
        with self._lock:
            policy_id = _check_id(policy_id, "policy_id")
            policy = self._policies.get(policy_id)
            if policy is None:
                raise UnknownPolicyError(f"unknown policy: {policy_id!r}")
            return policy

    def resource_ids(self) -> tuple[str, ...]:
        """Registered resource ids, sorted."""
        with self._lock:
            return tuple(sorted(self._resources))

    def policy_ids(self) -> tuple[str, ...]:
        """Defined policy ids, sorted."""
        with self._lock:
            return tuple(sorted(self._policies))

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Booked audit events, oldest first (ids + pins only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, tag, untag, policy, evaluate, pins."""
    mgr = ResourceTagging()
    res = mgr.register("i-123", "ec2:instance", seq=1)
    assert res.verify() and res.resource_id == "i-123"
    app = mgr.tag("i-123", {"env": "prod", "owner": "ops"}, seq=2)
    assert app.verify()
    assert mgr.tags("i-123") == {"env": "prod", "owner": "ops"}
    # Upsert merges: latest value wins, other keys survive.
    mgr.tag("i-123", {"env": "staging"}, seq=3)
    assert mgr.tags("i-123") == {"env": "staging", "owner": "ops"}
    pol = mgr.policy(
        "baseline",
        ("env", "owner"),
        seq=4,
        allowed_values={"env": ("prod", "staging")},
    )
    assert pol.verify()
    ev = mgr.evaluate("baseline", "i-123", seq=5)
    assert ev.verify() and ev.compliant and ev.violations == ()
    # Removing a required key breaks compliance (as data).
    mgr.untag("i-123", ("owner",), seq=6)
    ev2 = mgr.evaluate("baseline", "i-123", seq=7)
    assert ev2.verify() and not ev2.compliant
    assert ev2.violations == (("owner", "missing"),)
    # Values never cross the audit boundary.
    for event in mgr.audit_log():
        assert "value" not in event["detail"]
        assert "values" not in event["detail"]
        assert "tags" not in event["detail"]
    print("resource-tagging OK: register, tag, untag, policy, evaluate, pins, audit")


if __name__ == "__main__":
    main()
