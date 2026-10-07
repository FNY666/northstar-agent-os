"""Blue-green deployment controller: zero-downtime cutover between two versions.

Research note: blue-green deployment (one of the classic deployment safety
patterns, alongside canary and rolling updates) keeps two production-like
environments — "blue" (current) and "green" (next) — and routes all traffic
to exactly one of them. Cutover is a single atomic switch, so a bad release
can be rolled back by flipping back, with no partial-migration state. In an
agent-runtime context this is the shape used for model/policy/config
version swaps: both variants are fully staged, and the controller records
*which one is serving* as a single auditable fact.

* **Two variants, one active** — ``Deployment`` names a blue and a green
  version; exactly one is ``active`` at any time. The inactive variant is
  the staged fallback, never "half live".
* **Switch** — atomically flips ``active``. The record keeps ``previous``
  (the variant that was serving before the switch) so a rollback target
  always exists.
* **Rollback** — returns ``active`` to ``previous``. Fail-closed: rolling
  back with no prior switch raises ``BlueGreenError`` instead of
  inventing a target.
* **No wall-clock** — all seqs are caller-supplied ints; the module is
  deterministic and replayable. Immutability is enforced by frozen
  records: ``switch`` / ``rollback`` return new ``Deployment`` records,
  never mutate in place.

Honest scope: this is the *controller state machine*, not a load
balancer — it does not move traffic itself, drain connections, or run
health checks. ``active="green"`` means "the controller records green as
serving", never "green is healthy". Health gating, readiness probes, and
drain behavior are the host's job; the controller records the decision
and pins it for audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

#: Module version.
BLUE_GREEN_DEPLOY_VERSION = "blue-green-deploy.v1"

#: Schema pin for records produced by this module.
BLUE_GREEN_DEPLOY_SCHEMA = "northstar.blue-green-deploy.v1"

#: Valid values for the ``active`` slot.
VALID_SLOTS = ("blue", "green")


class BlueGreenError(Exception):
    """Raised when a deployment transition is structurally impossible."""


def _check_version(name: str, value: Any) -> str:
    """Validate a version label; fail closed on malformed input."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BlueGreenError(f"{name} must be a non-empty str, got {type(value).__name__}")
    if not value.strip():
        raise BlueGreenError(f"{name} must be a non-empty str")
    return value


def _check_slot(value: Any) -> str:
    """Validate an active-slot value; fail closed."""
    if isinstance(value, bool) or not isinstance(value, str) or value not in VALID_SLOTS:
        raise BlueGreenError(f"active must be one of {VALID_SLOTS}, got {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    """Validate a caller-supplied sequence number; fail closed."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BlueGreenError(f"seq must be a non-negative int, got {seq!r}")
    return seq


@dataclass(frozen=True)
class Deployment:
    """A blue-green deployment record.

    ``blue_version`` / ``green_version`` name the two staged variants;
    ``active`` names which one is serving; ``previous`` names the variant
    that was serving before the most recent switch (``None`` until the
    first switch, so a rollback target never gets invented); ``switches``
    counts total cutovers for audit.
    """

    blue_version: str
    green_version: str
    active: str
    previous: str | None = None
    switches: int = 0

    def __post_init__(self) -> None:
        _check_version("blue_version", self.blue_version)
        _check_version("green_version", self.green_version)
        _check_slot(self.active)
        if self.previous is not None:
            _check_slot(self.previous)
        if isinstance(self.switches, bool) or not isinstance(self.switches, int) or self.switches < 0:
            raise BlueGreenError(f"switches must be a non-negative int, got {self.switches!r}")
        if self.previous == self.active:
            raise BlueGreenError("previous must differ from active")

    def serving(self) -> str:
        """Return the version string that is currently serving."""
        return self.blue_version if self.active == "blue" else self.green_version

    def staged(self) -> str:
        """Return the version string that is staged (not serving)."""
        return self.green_version if self.active == "blue" else self.blue_version

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": BLUE_GREEN_DEPLOY_SCHEMA,
            "blue_version": self.blue_version,
            "green_version": self.green_version,
            "active": self.active,
            "previous": self.previous,
            "switches": self.switches,
        }


@dataclass(frozen=True)
class SwitchRecord:
    """Audit record for a single switch or rollback transition."""

    deployment: Deployment
    action: str  # "switch" or "rollback"
    seq: int

    def __post_init__(self) -> None:
        if self.action not in ("switch", "rollback"):
            raise BlueGreenError(f"action must be 'switch' or 'rollback', got {self.action!r}")
        _check_seq(self.seq)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": BLUE_GREEN_DEPLOY_SCHEMA,
            "action": self.action,
            "seq": self.seq,
            "deployment": self.deployment.as_dict(),
        }


def create(blue_version: str, green_version: str, active: str = "blue") -> Deployment:
    """Create a fresh deployment record with ``active`` serving."""
    return Deployment(
        blue_version=_check_version("blue_version", blue_version),
        green_version=_check_version("green_version", green_version),
        active=_check_slot(active),
    )


def switch(deployment: Deployment, seq: int) -> Tuple[Deployment, SwitchRecord]:
    """Atomically flip which variant is serving.

    Returns ``(new_deployment, record)``. The old ``active`` becomes
    ``previous`` so a rollback target always exists afterwards.
    """
    if not isinstance(deployment, Deployment):
        raise BlueGreenError(f"deployment must be a Deployment, got {type(deployment).__name__}")
    _check_seq(seq)
    new_active = "green" if deployment.active == "blue" else "blue"
    new_deployment = Deployment(
        blue_version=deployment.blue_version,
        green_version=deployment.green_version,
        active=new_active,
        previous=deployment.active,
        switches=deployment.switches + 1,
    )
    return new_deployment, SwitchRecord(deployment=new_deployment, action="switch", seq=seq)


def rollback(deployment: Deployment, seq: int) -> Tuple[Deployment, SwitchRecord]:
    """Return serving traffic to the variant that served before the last switch.

    Fail-closed: if no switch has happened yet (``previous is None``) there
    is nothing to roll back to and ``BlueGreenError`` is raised instead of
    guessing.
    """
    if not isinstance(deployment, Deployment):
        raise BlueGreenError(f"deployment must be a Deployment, got {type(deployment).__name__}")
    _check_seq(seq)
    if deployment.previous is None:
        raise BlueGreenError("nothing to roll back to: no prior switch recorded")
    new_deployment = Deployment(
        blue_version=deployment.blue_version,
        green_version=deployment.green_version,
        active=deployment.previous,
        previous=deployment.active,
        switches=deployment.switches + 1,
    )
    return new_deployment, SwitchRecord(deployment=new_deployment, action="rollback", seq=seq)


def blue_green_audit_event(record: SwitchRecord, outcome: str) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1``-style record for a switch/rollback."""
    if not isinstance(record, SwitchRecord):
        raise BlueGreenError(f"record must be a SwitchRecord, got {type(record).__name__}")
    if outcome not in ("completed", "failed"):
        raise BlueGreenError(f"outcome must be 'completed' or 'failed', got {outcome!r}")
    return {
        "schema": "audit.ndjson/1",
        "event": f"blue-green.{record.action}",
        "outcome": outcome,
        "seq": record.seq,
        "serving": record.deployment.serving(),
        "active": record.deployment.active,
        "previous": record.deployment.previous,
        "switches": record.deployment.switches,
    }


def main() -> None:
    d = create("v1.2.0", "v1.3.0")
    assert d.serving() == "v1.2.0" and d.staged() == "v1.3.0"
    d2, r1 = switch(d, seq=1)
    assert d2.serving() == "v1.3.0" and d2.previous == "blue"
    d3, r2 = rollback(d2, seq=2)
    assert d3.serving() == "v1.2.0" and d3.active == "blue"
    ev = blue_green_audit_event(r2, "completed")
    assert ev["event"] == "blue-green.rollback" and ev["outcome"] == "completed"
    print("blue-green-deploy OK: switch, rollback, audit")


if __name__ == "__main__":
    main()
