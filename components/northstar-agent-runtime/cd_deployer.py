"""CD deployer: progressive-delivery orchestration as a deterministic state machine.

Research note: progressive delivery limits blast radius by shifting traffic
or instances to a new version in steps instead of all at once (canary
analysis a la Kayenta/Spinnaker, Argo Rollouts, blue-green a la Fowler,
Kubernetes rolling updates). For an agent runtime the same discipline
applies to agent-build, skill-pack, or policy-bundle rollouts: the host
advances one step at a time, watches the audit trail between steps, and
can pause or roll back before the new version owns the fleet.

* **Strategies** — ``canary`` (stepped traffic percentages), ``blue_green``
  (provision, verify, then a single cutover), ``rolling`` (step-wise
  instance replacement), ``recreate`` (stop-all-then-start: one step,
  fastest, riskiest — made explicit rather than hidden).
* **Deterministic** — every transition is driven by caller-supplied int
  seqs; no wall-clock, no RNG, no threads spawned. The same op sequence
  replays to the same state and the same digest pins.
* **Fail-closed** — unknown services, unknown strategies, deploying while
  a rollout is in progress, advancing a paused rollout, advancing past
  the last step, rolling back with nothing live, and malformed inputs
  all raise; they never silently mutate rollout state.

Honest scope: this module books the *decisions* (which step the rollout
is on, which version is stable), never the *verdicts* — it cannot tell
whether the new version is healthy (error-rate or audit analysis is the
host's job), and a completed rollout means "the steps were advanced",
never "the version is good". It owns no sockets, no processes, no
actual traffic: the host applies each ``AdvanceReport`` and reports
back via the next call.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # canonicalizer shared with the rest of the batch line
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version pin.
CD_DEPLOYER_VERSION = "cd-deployer.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cd-deployer.v1"

#: Closed strategy vocabulary. There is no fifth strategy; an unknown
#: name is malformed input, not a default.
STRATEGIES: Tuple[str, ...] = ("canary", "blue_green", "rolling", "recreate")

#: Default canary traffic ladder: last entry is always 100%.
DEFAULT_CANARY_STEPS: Tuple[float, ...] = (1.0, 5.0, 25.0, 50.0, 100.0)

#: Default rolling batch ladder (fraction of instances on the new version).
DEFAULT_ROLLING_STEPS: Tuple[float, ...] = (25.0, 50.0, 75.0, 100.0)

#: Audit event names.
AUDIT_KINDS: Tuple[str, ...] = (
    "service-registered",
    "deployed",
    "advanced",
    "completed",
    "paused",
    "resumed",
    "rolled-back",
    "rejected",
)


class CDDeployerError(Exception):
    """Base error for CD deployer misuse and malformed input."""


class UnknownServiceError(CDDeployerError):
    """Raised when an operation names a service that was never registered."""


class DeploymentInProgressError(CDDeployerError):
    """Raised when deploying while a rollout is already live for the service."""


class NoLiveDeploymentError(CDDeployerError):
    """Raised when an op needs a live rollout and none exists."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_text(value: Any, field_name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        raise TypeError(f"{field_name} must be a non-empty str")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError("seq must be a non-negative int")
    return value


def _check_pct(value: Any, field_name: str = "traffic_pct") -> float:
    """Traffic share in [0, 100]. Zero is meaningful for pre-cutover steps
    (e.g. blue-green provision/verify receive no live traffic yet)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be a real number in [0, 100]")
    pct = float(value)
    if pct != pct or pct in (float("inf"), float("-inf")):
        raise ValueError(f"{field_name} must be finite")
    if pct < 0.0 or pct > 100.0:
        raise ValueError(f"{field_name} must be within [0, 100]")
    return pct


def _check_canary_steps(steps: Any) -> Tuple[float, ...]:
    if not isinstance(steps, (tuple, list)) or not steps:
        raise TypeError("steps must be a non-empty sequence of percentages")
    clean = tuple(_check_pct(s, f"steps[{i}]") for i, s in enumerate(steps))
    if any(s == 0.0 for s in clean):
        raise ValueError("canary steps must each be > 0")
    for prev, cur in zip(clean, clean[1:]):
        if cur <= prev:
            raise ValueError("canary steps must be strictly increasing")
    if clean[-1] != 100.0:
        raise ValueError("canary steps must end at exactly 100.0")
    return clean


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(payload))


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RolloutStep:
    """One rollout step: what fraction of traffic/instances is new-version."""

    index: int
    name: str
    target_pct: float

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int) or self.index < 0:
            raise TypeError("index must be a non-negative int")
        _check_text(self.name, "name")
        object.__setattr__(self, "target_pct", _check_pct(self.target_pct))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "index": self.index,
            "name": self.name,
            "target_pct": self.target_pct,
        }


@dataclass(frozen=True)
class ServiceRecord:
    """A registered service and its initial stable version."""

    service: str
    stable_version: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "stable_version": self.stable_version,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DeploymentRecord:
    """A started deployment: service, target, strategy, and the step plan."""

    service: str
    version: str
    strategy: str
    steps: Tuple[RolloutStep, ...]
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "version": self.version,
            "strategy": self.strategy,
            "steps": [s.as_dict() for s in self.steps],
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AdvanceReport:
    """Record of one completed rollout step."""

    service: str
    version: str
    strategy: str
    completed_step: RolloutStep
    current_traffic_pct: float
    remaining_steps: int
    completed: bool
    stable_version: str  # updated only when completed is True
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "version": self.version,
            "strategy": self.strategy,
            "completed_step": self.completed_step.as_dict(),
            "current_traffic_pct": self.current_traffic_pct,
            "remaining_steps": self.remaining_steps,
            "completed": self.completed,
            "stable_version": self.stable_version,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PauseReport:
    """Record of a paused rollout."""

    service: str
    version: str
    completed_steps: int
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "version": self.version,
            "completed_steps": self.completed_steps,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ResumeReport:
    """Record of a resumed rollout."""

    service: str
    version: str
    completed_steps: int
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "version": self.version,
            "completed_steps": self.completed_steps,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class RollbackReport:
    """Record of a rolled-back rollout: the new version was dropped."""

    service: str
    dropped_version: str
    restored_stable: str
    completed_steps: int
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "dropped_version": self.dropped_version,
            "restored_stable": self.restored_stable,
            "completed_steps": self.completed_steps,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DeploymentStatus:
    """Current per-service status: stable version plus any live rollout."""

    service: str
    stable_version: str
    live: bool
    strategy: Optional[str] = None
    target_version: Optional[str] = None
    current_traffic_pct: float = 0.0
    completed_steps: int = 0
    total_steps: int = 0
    paused: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "service": self.service,
            "stable_version": self.stable_version,
            "live": self.live,
            "strategy": self.strategy,
            "target_version": self.target_version,
            "current_traffic_pct": self.current_traffic_pct,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "paused": self.paused,
        }


# ---------------------------------------------------------------------------
# Live deployment (internal mutable state)
# ---------------------------------------------------------------------------


class _LiveDeployment:
    __slots__ = ("service", "version", "strategy", "steps", "completed", "paused")

    def __init__(
        self,
        service: str,
        version: str,
        strategy: str,
        steps: Tuple[RolloutStep, ...],
    ) -> None:
        self.service = service
        self.version = version
        self.strategy = strategy
        self.steps = steps
        self.completed = 0
        self.paused = False

    def current_traffic_pct(self) -> float:
        if self.completed == 0:
            return 0.0
        return self.steps[self.completed - 1].target_pct


# ---------------------------------------------------------------------------
# Deployer
# ---------------------------------------------------------------------------


class CDDeployer:
    """Progressive-delivery orchestrator: strategies, rollout, rollback."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stable: Dict[str, str] = {}
        self._live: Dict[str, _LiveDeployment] = {}
        self._events: List[Dict[str, Any]] = []

    # -- service registry ---------------------------------------------------

    def register_service(self, service: str, stable_version: str, seq: int) -> ServiceRecord:
        """Declare a service with its initial stable version."""
        service = _check_text(service, "service")
        stable_version = _check_text(stable_version, "stable_version")
        seq = _check_seq(seq)
        with self._lock:
            if service in self._stable:
                raise CDDeployerError(f"service {service!r} already registered")
            self._stable[service] = stable_version
            record = ServiceRecord(
                service=service,
                stable_version=stable_version,
                seq=seq,
                digest=_digest({
                    "module": CD_DEPLOYER_VERSION,
                    "service": service,
                    "stable_version": stable_version,
                    "seq": seq,
                }),
            )
            self._events.append({"event": "service-registered", "service": service,
                                 "stable_version": stable_version, "seq": seq})
            return record

    # -- deployment lifecycle -----------------------------------------------

    def deploy(self, service: str, version: str, strategy: str, seq: int) -> DeploymentRecord:
        """Start a deployment. Refused while a rollout is live for the service."""
        service = _check_text(service, "service")
        version = _check_text(version, "version")
        seq = _check_seq(seq)
        if strategy not in STRATEGIES:
            raise CDDeployerError(
                f"unknown strategy {strategy!r}; expected one of {STRATEGIES}"
            )
        with self._lock:
            if service not in self._stable:
                raise UnknownServiceError(f"unknown service {service!r}")
            if service in self._live:
                raise DeploymentInProgressError(
                    f"rollout of {self._live[service].version!r} already live for "
                    f"{service!r}; advance, pause, or roll back first"
                )
            if version == self._stable[service]:
                raise CDDeployerError(
                    f"version {version!r} is already the stable version for {service!r}"
                )
            steps = self._plan_steps(strategy, None)
            self._live[service] = _LiveDeployment(service, version, strategy, steps)
            record = DeploymentRecord(
                service=service,
                version=version,
                strategy=strategy,
                steps=steps,
                seq=seq,
                digest=_digest({
                    "module": CD_DEPLOYER_VERSION,
                    "service": service,
                    "version": version,
                    "strategy": strategy,
                    "steps": [s.name for s in steps],
                    "seq": seq,
                }),
            )
            self._events.append({"event": "deployed", "service": service,
                                 "version": version, "strategy": strategy, "seq": seq})
            return record

    def canary(
        self, service: str, version: str, steps: Sequence[Any], seq: int
    ) -> DeploymentRecord:
        """Start a canary deployment with an explicit traffic ladder.

        ``steps`` must be strictly increasing percentages ending at 100.0.
        """
        service = _check_text(service, "service")
        version = _check_text(version, "version")
        seq = _check_seq(seq)
        clean_steps = _check_canary_steps(steps)
        with self._lock:
            if service not in self._stable:
                raise UnknownServiceError(f"unknown service {service!r}")
            if service in self._live:
                raise DeploymentInProgressError(
                    f"rollout of {self._live[service].version!r} already live for "
                    f"{service!r}; advance, pause, or roll back first"
                )
            if version == self._stable[service]:
                raise CDDeployerError(
                    f"version {version!r} is already the stable version for {service!r}"
                )
            planned = self._plan_steps("canary", clean_steps)
            self._live[service] = _LiveDeployment(service, version, "canary", planned)
            record = DeploymentRecord(
                service=service,
                version=version,
                strategy="canary",
                steps=planned,
                seq=seq,
                digest=_digest({
                    "module": CD_DEPLOYER_VERSION,
                    "service": service,
                    "version": version,
                    "strategy": "canary",
                    "steps": list(clean_steps),
                    "seq": seq,
                }),
            )
            self._events.append({"event": "deployed", "service": service,
                                 "version": version, "strategy": "canary", "seq": seq})
            return record

    def advance(self, service: str, seq: int) -> AdvanceReport:
        """Complete the next rollout step. The final step promotes the version."""
        service = _check_text(service, "service")
        seq = _check_seq(seq)
        with self._lock:
            live = self._live.get(service)
            if live is None:
                if service not in self._stable:
                    raise UnknownServiceError(f"unknown service {service!r}")
                raise NoLiveDeploymentError(f"no live rollout for {service!r}")
            if live.paused:
                raise CDDeployerError(
                    f"rollout of {live.version!r} is paused; resume before advancing"
                )
            step = live.steps[live.completed]
            live.completed += 1
            traffic = live.current_traffic_pct()
            remaining = len(live.steps) - live.completed
            completed = remaining == 0
            if completed:
                self._stable[service] = live.version
                del self._live[service]
                self._events.append({"event": "completed", "service": service,
                                     "version": live.version, "seq": seq})
            else:
                self._events.append({"event": "advanced", "service": service,
                                     "version": live.version, "step": step.name,
                                     "traffic_pct": traffic, "seq": seq})
            return AdvanceReport(
                service=service,
                version=live.version,
                strategy=live.strategy,
                completed_step=step,
                current_traffic_pct=traffic,
                remaining_steps=remaining,
                completed=completed,
                stable_version=self._stable[service],
                seq=seq,
                digest=_digest({
                    "module": CD_DEPLOYER_VERSION,
                    "service": service,
                    "version": live.version,
                    "strategy": live.strategy,
                    "step": step.name,
                    "completed": completed,
                    "seq": seq,
                }),
            )

    def pause(self, service: str, seq: int) -> PauseReport:
        """Pause a live rollout; advancing is refused until resumed."""
        service = _check_text(service, "service")
        seq = _check_seq(seq)
        with self._lock:
            live = self._live.get(service)
            if live is None:
                if service not in self._stable:
                    raise UnknownServiceError(f"unknown service {service!r}")
                raise NoLiveDeploymentError(f"no live rollout for {service!r}")
            if live.paused:
                raise CDDeployerError(f"rollout of {live.version!r} is already paused")
            live.paused = True
            self._events.append({"event": "paused", "service": service,
                                 "version": live.version, "seq": seq})
            return PauseReport(service=service, version=live.version,
                               completed_steps=live.completed, seq=seq)

    def resume(self, service: str, seq: int) -> ResumeReport:
        """Resume a paused rollout."""
        service = _check_text(service, "service")
        seq = _check_seq(seq)
        with self._lock:
            live = self._live.get(service)
            if live is None:
                if service not in self._stable:
                    raise UnknownServiceError(f"unknown service {service!r}")
                raise NoLiveDeploymentError(f"no live rollout for {service!r}")
            if not live.paused:
                raise CDDeployerError(f"rollout of {live.version!r} is not paused")
            live.paused = False
            self._events.append({"event": "resumed", "service": service,
                                 "version": live.version, "seq": seq})
            return ResumeReport(service=service, version=live.version,
                                completed_steps=live.completed, seq=seq)

    def rollback(self, service: str, seq: int) -> RollbackReport:
        """Drop the live rollout; the stable version is unchanged."""
        service = _check_text(service, "service")
        seq = _check_seq(seq)
        with self._lock:
            live = self._live.get(service)
            if live is None:
                if service not in self._stable:
                    raise UnknownServiceError(f"unknown service {service!r}")
                raise NoLiveDeploymentError(f"no live rollout for {service!r}")
            dropped = live.version
            done = live.completed
            del self._live[service]
            report = RollbackReport(
                service=service,
                dropped_version=dropped,
                restored_stable=self._stable[service],
                completed_steps=done,
                seq=seq,
                digest=_digest({
                    "module": CD_DEPLOYER_VERSION,
                    "service": service,
                    "dropped_version": dropped,
                    "completed_steps": done,
                    "seq": seq,
                }),
            )
            self._events.append({"event": "rolled-back", "service": service,
                                 "dropped_version": dropped,
                                 "restored_stable": self._stable[service], "seq": seq})
            return report

    # -- views --------------------------------------------------------------

    def status(self, service: str) -> DeploymentStatus:
        service = _check_text(service, "service")
        with self._lock:
            if service not in self._stable:
                raise UnknownServiceError(f"unknown service {service!r}")
            live = self._live.get(service)
            if live is None:
                return DeploymentStatus(service=service,
                                        stable_version=self._stable[service], live=False)
            return DeploymentStatus(
                service=service,
                stable_version=self._stable[service],
                live=True,
                strategy=live.strategy,
                target_version=live.version,
                current_traffic_pct=live.current_traffic_pct(),
                completed_steps=live.completed,
                total_steps=len(live.steps),
                paused=live.paused,
            )

    def services(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._stable))

    def events(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._events)

    # -- planning -----------------------------------------------------------

    @staticmethod
    def _plan_steps(
        strategy: str, canary_steps: Optional[Tuple[float, ...]]
    ) -> Tuple[RolloutStep, ...]:
        if strategy == "canary":
            ladder = canary_steps if canary_steps is not None else DEFAULT_CANARY_STEPS
            return tuple(
                RolloutStep(index=i, name=f"canary-{pct:g}%", target_pct=pct)
                for i, pct in enumerate(ladder)
            )
        if strategy == "blue_green":
            return (
                RolloutStep(index=0, name="provision-green", target_pct=0.0),
                RolloutStep(index=1, name="verify-green", target_pct=0.0),
                RolloutStep(index=2, name="cutover", target_pct=100.0),
            )
        if strategy == "rolling":
            return tuple(
                RolloutStep(index=i, name=f"replace-batch-{i + 1}", target_pct=pct)
                for i, pct in enumerate(DEFAULT_ROLLING_STEPS)
            )
        # recreate: single step. Fastest, riskiest — explicit, not hidden.
        return (RolloutStep(index=0, name="replace-all", target_pct=100.0),)


def cd_deployer_audit_event(kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1``-style record for a CD deployer event."""
    if kind not in AUDIT_KINDS:
        raise CDDeployerError(f"unknown audit kind {kind!r}; expected one of {AUDIT_KINDS}")
    _check_seq(seq)
    record: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": f"cd-deployer.{kind}",
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        record["detail"] = dict(detail)
    return record


def main() -> None:
    deployer = CDDeployer()
    deployer.register_service("agent-api", "v1.0.0", seq=0)

    # Canary ladder: advance through all steps, promoting at the end.
    record = deployer.deploy("agent-api", "v1.1.0", "canary", seq=1)
    assert [s.target_pct for s in record.steps] == [1.0, 5.0, 25.0, 50.0, 100.0]
    status = deployer.status("agent-api")
    assert status.live and status.current_traffic_pct == 0.0
    for _ in range(4):
        report = deployer.advance("agent-api", seq=2)
        assert not report.completed
    final = deployer.advance("agent-api", seq=3)
    assert final.completed and final.stable_version == "v1.1.0"
    assert deployer.status("agent-api").stable_version == "v1.1.0"

    # Pause / resume / rollback.
    deployer.deploy("agent-api", "v1.2.0", "rolling", seq=4)
    deployer.pause("agent-api", seq=5)
    try:
        deployer.advance("agent-api", seq=6)
    except CDDeployerError:
        pass
    else:  # pragma: no cover
        raise AssertionError("advance on paused rollout must fail")
    deployer.resume("agent-api", seq=7)
    report = deployer.rollback("agent-api", seq=8)
    assert report.restored_stable == "v1.1.0"
    assert report.dropped_version == "v1.2.0"

    print("cd-deployer OK: canary, pause/resume, rollback, promotion")


if __name__ == "__main__":
    main()
