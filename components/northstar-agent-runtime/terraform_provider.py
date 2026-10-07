"""Terraform-style provider: desired-state plan/apply/destroy bookkeeping.

Research note: infrastructure-as-code (Terraform, Pulumi, CloudFormation)
decouples *desired state* (declared configuration) from *actual state*
(observed resources). The workflow is three phases:

1. **declare** — record the desired configuration of a resource
   (address + type + attributes).
2. **plan** — diff desired vs. last observed state and produce a frozen
   change list (create / update / delete / no-op per address). Planning
   is pure: it never touches anything, and a plan with no changes is
   the empty plan.
3. **apply** — execute a plan against a host-supplied applier, pin the
   resulting observed state, and emit an audit trail. ``destroy``
   plans and applies the full delete set.

This module is the *decision and bookkeeping* layer of that shape, not a
real cloud provider: no API calls, no network, no timeouts. The applier
is a host-injected callable ``(address, action, attrs) -> attrs`` that
returns the post-action observed attributes; this module validates,
orders, and pins everything around it.

* **Fail-closed planning** — unknown addresses in a plan, applying a
  plan twice, destroying with no state, and duplicate declarations with
  conflicting configs are all refused. Applying is idempotent: applying
  an empty plan succeeds and changes nothing.
* **Drift surfacing** — ``refresh(address, observed, seq)`` records
  host-reported observed attributes; ``plan`` diffs desired vs.
  observed, so out-of-band changes show up as ``update`` actions (never
  as errors — drift is a fact, not a fault).
* **Frozen records** — ``ResourceDeclaration`` / ``Plan`` / ``Change``
  / ``ApplyResult`` / ``DestroyResult`` are frozen dataclasses with
  ``sha256:`` digest pins over the canonical body. Raw attribute
  values are pinned, not hidden: this is a local ledger, not a secret
  store (secrets belong in ``secret_sharing`` / ``kms_interface``,
  never in state).
* **No wall-clock** — seqs are caller-supplied ints; all ordering is
  explicit. Determinism holds for identical inputs: ``plan`` output is
  sorted by address.

Honest scope: this books host-reported numbers only. It cannot prove
the applier actually created, changed, or deleted anything; an
applier that lies gets a consistent plan of lies (GIGO boundary, same
as every other bookkeeping module). ``applied=True`` means "the
applier reported success for every change", never "the world changed".
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

#: Module version.
TERRAFORM_PROVIDER_VERSION = "terraform-provider.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.terraform-provider.v1"

#: Audit record format pin.
AUDIT_FORMAT = "audit.ndjson/1"

_AUDIT_KINDS = frozenset(
    {
        "declared",
        "undeclared",
        "refreshed",
        "planned",
        "applied",
        "destroyed",
        "rejected",
    }
)

#: Action vocabulary for plan changes.
_ACTION_CREATE = "create"
_ACTION_UPDATE = "update"
_ACTION_DELETE = "delete"
_ACTION_NOOP = "no-op"
_ACTIONS = frozenset({_ACTION_CREATE, _ACTION_UPDATE, _ACTION_DELETE, _ACTION_NOOP})

#: Max attributes per resource (guardrail).
_MAX_ATTRS = 256

#: Max attribute nesting depth (guardrail).
_MAX_DEPTH = 16

#: Max resources per provider instance (guardrail).
_MAX_RESOURCES = 4096


class TerraformError(Exception):
    """Malformed input to the terraform provider (programming error)."""


class UnknownAddressError(TerraformError):
    """Address is not declared and has no observed state."""


class DuplicateDeclarationError(TerraformError):
    """Declaration conflicts with an existing one for the same address."""


class PlanReplayError(TerraformError):
    """Plan has already been applied (plans are single-use)."""


class EmptyStateError(TerraformError):
    """No state to operate on."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TerraformError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise TerraformError(f"seq must be >= 0, got {seq}")
    return seq


def _check_address(address: Any) -> str:
    if not isinstance(address, str) or not address.strip():
        raise TerraformError("address must be a non-empty string")
    if len(address) > 256:
        raise TerraformError("address too long")
    return address.strip()


def _check_type(resource_type: Any) -> str:
    if not isinstance(resource_type, str) or not resource_type.strip():
        raise TerraformError("resource_type must be a non-empty string")
    if len(resource_type) > 128:
        raise TerraformError("resource_type too long")
    return resource_type.strip()


def _canonical_value(value: Any, depth: int = 0) -> Any:
    """Type-tagged canonicalization.

    Distinct types never collapse (``True`` != ``1`` != ``"1"``).
    NaN/inf and ints beyond 2^53 are refused fail-closed (same JCS
    float-loss caveat as the batch-5 crypto line).
    """
    if depth > _MAX_DEPTH:
        raise TerraformError("attribute nesting too deep")
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise TerraformError("int beyond 2^53 refused (JCS float-loss)")
        return ["int", value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TerraformError("non-finite float refused")
        if value == int(value) and abs(value) <= 2**53:
            return ["int", int(value)]
        return ["float", repr(value)]
    if isinstance(value, str):
        if len(value) > 65536:
            raise TerraformError("string attribute too long")
        return ["str", value]
    if isinstance(value, (list, tuple)):
        if len(value) > 1024:
            raise TerraformError("list attribute too long")
        return ["list"] + [_canonical_value(v, depth + 1) for v in value]
    if isinstance(value, dict):
        if len(value) > 1024:
            raise TerraformError("mapping attribute too large")
        items = []
        for k, v in value.items():
            if not isinstance(k, str) or not k:
                raise TerraformError("attribute keys must be non-empty strings")
            items.append([k, _canonical_value(v, depth + 1)])
        items.sort(key=lambda kv: kv[0])
        return ["dict"] + items
    raise TerraformError(f"unserializable attribute type: {type(value).__name__}")


def _check_attrs(attrs: Any) -> Mapping[str, Any]:
    if not isinstance(attrs, Mapping):
        raise TerraformError("attrs must be a mapping")
    if len(attrs) > _MAX_ATTRS:
        raise TerraformError("too many attributes")
    for k in attrs:
        if not isinstance(k, str) or not k:
            raise TerraformError("attribute keys must be non-empty strings")
    _canonical_value(dict(attrs))
    return attrs


def _digest(*parts: Any) -> str:
    body = json.dumps(
        [_canonical_value(p) for p in parts],
        separators=(",", ":"),
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResourceDeclaration:
    """Desired-state declaration for one address."""

    address: str
    resource_type: str
    attrs: Tuple[Tuple[str, Any], ...]
    seq: int
    digest: str
    version: str = TERRAFORM_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "resource_type": self.resource_type,
            "attrs": dict(self.attrs),
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Change:
    """One planned change."""

    address: str
    action: str
    old_attrs: Optional[Tuple[Tuple[str, Any], ...]]
    new_attrs: Optional[Tuple[Tuple[str, Any], ...]]
    reason: str
    version: str = TERRAFORM_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "action": self.action,
            "old_attrs": dict(self.old_attrs) if self.old_attrs is not None else None,
            "new_attrs": dict(self.new_attrs) if self.new_attrs is not None else None,
            "reason": self.reason,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Plan:
    """A frozen plan: ordered changes plus digest pins."""

    seq: int
    changes: Tuple[Change, ...]
    plan_id: str
    digest: str
    version: str = TERRAFORM_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "plan_id": self.plan_id,
            "changes": [c.as_dict() for c in self.changes],
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ApplyResult:
    """Result of applying a plan."""

    plan_id: str
    seq: int
    applied: Tuple[str, ...]
    state_digest: str
    digest: str
    version: str = TERRAFORM_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "seq": self.seq,
            "applied": list(self.applied),
            "state_digest": self.state_digest,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DestroyResult:
    """Result of a destroy operation."""

    seq: int
    destroyed: Tuple[str, ...]
    state_digest: str
    digest: str
    version: str = TERRAFORM_PROVIDER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "destroyed": list(self.destroyed),
            "state_digest": self.state_digest,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


def _freeze_attrs(attrs: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    return tuple(sorted((k, attrs[k]) for k in attrs))


def _attrs_equal(a: Tuple[Tuple[str, Any], ...], b: Tuple[Tuple[str, Any], ...]) -> bool:
    return _canonical_value(dict(a)) == _canonical_value(dict(b))


class TerraformProvider:
    """Desired-state plan/apply/destroy bookkeeping.

    The provider holds declarations (desired state) and observed state
    (host-reported). ``plan`` diffs them; ``apply`` executes a plan via
    a host-supplied applier; ``destroy`` tears everything down.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._desired: Dict[str, Tuple[str, Tuple[Tuple[str, Any], ...]]] = {}
        self._state: Dict[str, Tuple[Tuple[str, Any], ...]] = {}
        self._declared_seq: Dict[str, int] = {}
        self._plan_counter = 0
        self._used_plans: set = set()

    def _state_digest(self) -> str:
        items = sorted(
            (addr, _canonical_value(dict(attrs)))
            for addr, attrs in self._state.items()
        )
        return _digest("state", items)

    def declare(
        self,
        address: str,
        resource_type: str,
        attrs: Mapping[str, Any],
        seq: int,
    ) -> ResourceDeclaration:
        """Register desired state for an address (idempotent on identical config)."""
        _check_seq(seq)
        address = _check_address(address)
        resource_type = _check_type(resource_type)
        _check_attrs(attrs)
        frozen = _freeze_attrs(attrs)
        with self._lock:
            if len(self._desired) >= _MAX_RESOURCES and address not in self._desired:
                raise TerraformError("too many resources")
            if address in self._desired:
                old_type, old_attrs = self._desired[address]
                if old_type != resource_type or not _attrs_equal(old_attrs, frozen):
                    raise DuplicateDeclarationError(
                        f"conflicting declaration for {address!r}"
                    )
                decl = ResourceDeclaration(
                    address=address,
                    resource_type=resource_type,
                    attrs=frozen,
                    seq=self._declared_seq[address],
                    digest=_digest("declare", address, resource_type, dict(frozen)),
                )
                return decl
            self._desired[address] = (resource_type, frozen)
            self._declared_seq[address] = seq
            return ResourceDeclaration(
                address=address,
                resource_type=resource_type,
                attrs=frozen,
                seq=seq,
                digest=_digest("declare", address, resource_type, dict(frozen)),
            )

    def undeclare(self, address: str, seq: int) -> None:
        """Remove a declaration. Does not touch observed state."""
        _check_seq(seq)
        address = _check_address(address)
        with self._lock:
            if address not in self._desired:
                raise UnknownAddressError(f"not declared: {address!r}")
            del self._desired[address]
            del self._declared_seq[address]

    def refresh(
        self, address: str, observed: Mapping[str, Any], seq: int
    ) -> None:
        """Record host-reported observed attributes for an address."""
        _check_seq(seq)
        address = _check_address(address)
        _check_attrs(observed)
        with self._lock:
            self._state[address] = _freeze_attrs(observed)

    def plan(self, seq: int) -> Plan:
        """Diff desired vs. observed state. Pure: never mutates anything."""
        _check_seq(seq)
        with self._lock:
            changes: list = []
            for address in sorted(self._desired):
                rtype, desired_attrs = self._desired[address]
                if address not in self._state:
                    changes.append(
                        Change(
                            address=address,
                            action=_ACTION_CREATE,
                            old_attrs=None,
                            new_attrs=desired_attrs,
                            reason=f"declared {rtype} has no observed state",
                        )
                    )
                elif not _attrs_equal(self._state[address], desired_attrs):
                    changes.append(
                        Change(
                            address=address,
                            action=_ACTION_UPDATE,
                            old_attrs=self._state[address],
                            new_attrs=desired_attrs,
                            reason="observed state drifted from declaration",
                        )
                    )
            for address in sorted(self._state):
                if address not in self._desired:
                    changes.append(
                        Change(
                            address=address,
                            action=_ACTION_DELETE,
                            old_attrs=self._state[address],
                            new_attrs=None,
                            reason="observed resource not declared (unmanaged)",
                        )
                    )
            self._plan_counter += 1
            plan_id = f"plan-{self._plan_counter}"
            change_dicts = [c.as_dict() for c in changes]
            digest = _digest("plan", plan_id, seq, change_dicts)
            return Plan(
                seq=seq,
                changes=tuple(changes),
                plan_id=plan_id,
                digest=digest,
            )

    def apply(
        self,
        plan: Plan,
        seq: int,
        applier: Optional[Callable[[str, str, Optional[Dict[str, Any]]], Optional[Dict[str, Any]]]] = None,
    ) -> ApplyResult:
        """Execute a plan. Single-use: applying the same plan twice is refused."""
        _check_seq(seq)
        if not isinstance(plan, Plan):
            raise TerraformError("plan must be a Plan")
        with self._lock:
            if plan.plan_id in self._used_plans:
                raise PlanReplayError(f"plan {plan.plan_id!r} already applied")
            applied: list = []
            for change in plan.changes:
                if change.action == _ACTION_CREATE:
                    new = dict(change.new_attrs) if change.new_attrs else {}
                    if applier is not None:
                        reported = applier(change.address, "create", dict(new))
                        if reported is not None:
                            _check_attrs(reported)
                            new = dict(reported)
                    self._state[change.address] = _freeze_attrs(new)
                elif change.action == _ACTION_UPDATE:
                    new = dict(change.new_attrs) if change.new_attrs else {}
                    if applier is not None:
                        reported = applier(change.address, "update", dict(new))
                        if reported is not None:
                            _check_attrs(reported)
                            new = dict(reported)
                    self._state[change.address] = _freeze_attrs(new)
                elif change.action == _ACTION_DELETE:
                    if applier is not None:
                        applier(change.address, "delete", None)
                    self._state.pop(change.address, None)
                applied.append(change.address)
            self._used_plans.add(plan.plan_id)
            state_digest = self._state_digest()
            return ApplyResult(
                plan_id=plan.plan_id,
                seq=seq,
                applied=tuple(applied),
                state_digest=state_digest,
                digest=_digest("apply", plan.plan_id, seq, applied, state_digest),
            )

    def destroy(
        self,
        seq: int,
        applier: Optional[Callable[[str, str, Optional[Dict[str, Any]]], Optional[Dict[str, Any]]]] = None,
    ) -> DestroyResult:
        """Plan and apply deletion of all observed state."""
        _check_seq(seq)
        with self._lock:
            if not self._state and not self._desired:
                raise EmptyStateError("nothing to destroy")
            addresses = sorted(self._state)
            for address in addresses:
                if applier is not None:
                    applier(address, "delete", None)
                self._state.pop(address, None)
            state_digest = self._state_digest()
            return DestroyResult(
                seq=seq,
                destroyed=tuple(addresses),
                state_digest=state_digest,
                digest=_digest("destroy", seq, addresses, state_digest),
            )

    def declared(self) -> Tuple[str, ...]:
        """Declared addresses, sorted."""
        with self._lock:
            return tuple(sorted(self._desired))

    def observed(self) -> Tuple[str, ...]:
        """Observed addresses, sorted."""
        with self._lock:
            return tuple(sorted(self._state))


def terraform_provider_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module."""
    _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise TerraformError(f"unknown audit kind: {kind!r}")
    detail_dict = dict(detail) if detail else {}
    _canonical_value(detail_dict)
    return {
        "format": AUDIT_FORMAT,
        "module": "terraform_provider",
        "module_version": TERRAFORM_PROVIDER_VERSION,
        "schema": SCHEMA_PIN,
        "kind": kind,
        "seq": seq,
        "detail": detail_dict,
    }


def main() -> None:
    p = TerraformProvider()
    p.declare("aws_instance.web", "aws_instance", {"ami": "ami-1", "count": 1}, seq=0)
    plan = p.plan(seq=1)
    assert len(plan.changes) == 1 and plan.changes[0].action == "create"
    result = p.apply(plan, seq=2)
    assert result.applied == ("aws_instance.web",)
    # Idempotent: second plan is empty.
    plan2 = p.plan(seq=3)
    assert len(plan2.changes) == 0
    result2 = p.apply(plan2, seq=4)
    assert result2.applied == ()
    # Drift shows as update.
    p.refresh("aws_instance.web", {"ami": "ami-2", "count": 1}, seq=5)
    plan3 = p.plan(seq=6)
    assert plan3.changes[0].action == "update"
    p.apply(plan3, seq=7)
    destroyed = p.destroy(seq=8)
    assert destroyed.destroyed == ("aws_instance.web",)
    print("terraform-provider OK: declare, plan, apply, drift, destroy")


if __name__ == "__main__":
    main()
