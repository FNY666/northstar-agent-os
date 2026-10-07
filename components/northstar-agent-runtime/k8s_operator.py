"""Kubernetes operator interface: CRD registry and reconcile-loop bookkeeping.

Research note: a Kubernetes operator implements the *controller pattern* —
watch custom resources (CRDs), compare *desired* state against *actual*
cluster state, and drive the actual state toward the desired state. The
load-bearing invariants are:

* **Level-triggered reconcile** — the loop re-examines every managed
  resource each pass; it does not depend on seeing every watch event
  (events are a latency optimization, not the correctness mechanism).
* **Desired vs observed diff** — reconcile emits a deterministic action plan
  (``create``/``update``/``delete``/``noop``) from the digest diff between
  the applied spec and the host-reported observed state.
* **Generation tracking** — every spec change bumps ``generation``; the
  controller reports ``observed_generation`` only when the observed state
  converges, so consumers can tell a stale status from a fresh one.
* **Fail-closed deletion** — ``delete()`` moves a resource to ``Terminating``;
  the reconcile plan emits the delete action, and the resource leaves the
  registry only after the host reports the observed state gone.

Honest scope: this module books *desired and reported states plus reconcile
decisions*. It has no cluster, no API server, no watch stream. Observed
state is host-reported — a host that lies about the cluster gets a
consistent ledger of lies (GIGO boundary, same as every other bookkeeping
module in this batch line). ``Ready`` means "reported state matches the
pinned spec digest", never "the workload is healthy".
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any

try:  # pragma: no cover - module must stay importable standalone
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


#: Module version.
K8S_OPERATOR_VERSION = "k8s-operator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.k8s-operator.v1"

#: Fixed vocabulary for audit events emitted by this module.
_AUDIT_KINDS = (
    "crd-registered",
    "applied",
    "observed",
    "reconciled",
    "deleted",
    "rejected",
)

#: Fixed vocabulary for reconcile actions.
_ACTIONS = ("create", "update", "delete", "noop")

#: Resource phases.
_PHASES = ("Pending", "Progressing", "Ready", "Terminating")

_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_KIND_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")


class K8sOperatorError(Exception):
    """Base class for k8s-operator errors."""


class UnknownCRDError(K8sOperatorError):
    """A kind was used before its CRD was registered."""


class DuplicateCRDError(K8sOperatorError):
    """A CRD was registered twice for the same (group, version, kind)."""


class UnknownResourceError(K8sOperatorError):
    """A resource name is not known to the operator."""


class DuplicateResourceError(K8sOperatorError):
    """A resource name was applied twice without delete."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise K8sOperatorError(f"{name} must be a non-negative int")
    return value


def _check_name(value: Any, name: str = "name") -> str:
    if not isinstance(value, str) or not value:
        raise K8sOperatorError(f"{name} must be a non-empty str")
    if not _NAME_RE.match(value):
        raise K8sOperatorError(
            f"{name} must be a DNS-1123 subdomain segment, got {value!r}"
        )
    if len(value) > 253:
        raise K8sOperatorError(f"{name} must be at most 253 characters")
    return value


def _check_kind(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise K8sOperatorError("kind must be a non-empty str")
    if not _KIND_RE.match(value):
        raise K8sOperatorError(
            f"kind must be PascalCase (start uppercase), got {value!r}"
        )
    return value


def _canonical_or_raise(value: Any, name: str) -> bytes:
    """Canonicalize a host-reported payload; reject non-canonicalizable junk."""
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise K8sOperatorError(f"{name} must not contain NaN/inf")
    try:
        return jcs_canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise K8sOperatorError(f"{name} is not canonicalizable: {exc}") from None


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class CRDRecord:
    """A registered CustomResourceDefinition."""

    group: str
    version: str
    kind: str
    crd_name: str
    schema_digest: str
    audit_seq: int
    schema: str = SCHEMA_PIN
    record_version: str = K8S_OPERATOR_VERSION


@dataclass(frozen=True)
class ResourceRecord:
    """A desired-state custom resource as applied."""

    name: str
    crd: str
    spec_digest: str
    generation: int
    phase: str
    audit_seq: int
    schema: str = SCHEMA_PIN
    record_version: str = K8S_OPERATOR_VERSION


@dataclass(frozen=True)
class ObservedState:
    """Host-reported actual cluster state for one resource."""

    name: str
    observed_digest: str | None
    audit_seq: int
    schema: str = SCHEMA_PIN
    record_version: str = K8S_OPERATOR_VERSION


@dataclass(frozen=True)
class ReconcileAction:
    """One planned action from a reconcile pass."""

    name: str
    action: str
    reason: str
    spec_digest: str
    observed_digest: str | None


@dataclass(frozen=True)
class ReconcileReport:
    """The frozen outcome of one reconcile pass."""

    pass_seq: int
    actions: tuple[ReconcileAction, ...]
    requeue: bool
    digest: str
    schema: str = SCHEMA_PIN
    record_version: str = K8S_OPERATOR_VERSION


@dataclass(frozen=True)
class StatusRecord:
    """A resource's status view: phase + generation convergence."""

    name: str
    phase: str
    generation: int
    observed_generation: int
    in_sync: bool
    schema: str = SCHEMA_PIN
    record_version: str = K8S_OPERATOR_VERSION


class K8sOperator:
    """Simulated operator: CRD registry + level-triggered reconcile ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._crds: dict[str, CRDRecord] = {}
        self._resources: dict[str, dict[str, Any]] = {}
        self._reconcile_passes = 0

    # -- CRD registry ----------------------------------------------------

    def register_crd(
        self, group: Any, version: Any, kind: Any, schema: Any, seq: Any
    ) -> CRDRecord:
        """Register a CustomResourceDefinition for one (group, version, kind)."""
        seq = _check_seq(seq)
        if not isinstance(group, str) or not group:
            raise K8sOperatorError("group must be a non-empty str")
        if not isinstance(version, str) or not version:
            raise K8sOperatorError("version must be a non-empty str")
        kind = _check_kind(kind)
        _canonical_or_raise(schema, "schema")
        key = f"{group}/{version}/{kind}"
        with self._lock:
            if key in self._crds:
                raise DuplicateCRDError(f"CRD already registered: {key}")
            record = CRDRecord(
                group=group,
                version=version,
                kind=kind,
                crd_name=f"{kind.lower()}s.{group}",
                schema_digest=_digest(schema),
                audit_seq=seq,
            )
            self._crds[key] = record
            return record

    def crds(self) -> tuple[str, ...]:
        """Registered CRD keys, sorted."""
        with self._lock:
            return tuple(sorted(self._crds))

    # -- Desired state -----------------------------------------------------

    def apply(self, name: Any, kind: Any, spec: Any, seq: Any) -> ResourceRecord:
        """Submit desired state for a custom resource (level-triggered input)."""
        seq = _check_seq(seq)
        name = _check_name(name)
        kind = _check_kind(kind)
        _canonical_or_raise(spec, "spec")
        with self._lock:
            if not any(c.kind == kind for c in self._crds.values()):
                raise UnknownCRDError(f"no CRD registered for kind {kind!r}")
            if name in self._resources:
                raise DuplicateResourceError(
                    f"resource {name!r} already applied (delete first)"
                )
            digest = _digest(spec)
            self._resources[name] = {
                "name": name,
                "kind": kind,
                "spec_digest": digest,
                "generation": 1,
                "observed_generation": 0,
                "phase": "Pending",
                "observed_digest": None,
                "terminating": False,
                "apply_seq": seq,
            }
            return self._record(name, seq)

    def update_spec(self, name: Any, spec: Any, seq: Any) -> ResourceRecord:
        """Change desired state; bumps generation and drops Ready to Progressing."""
        seq = _check_seq(seq)
        name = _check_name(name)
        _canonical_or_raise(spec, "spec")
        with self._lock:
            entry = self._require_live(name)
            digest = _digest(spec)
            if digest != entry["spec_digest"]:
                entry["spec_digest"] = digest
                entry["generation"] += 1
                if entry["phase"] == "Ready":
                    entry["phase"] = "Progressing"
            return self._record(name, seq)

    def delete(self, name: Any, seq: Any) -> ResourceRecord:
        """Request deletion; the reconcile plan emits the delete action."""
        seq = _check_seq(seq)
        name = _check_name(name)
        with self._lock:
            entry = self._require_live(name)
            entry["terminating"] = True
            entry["phase"] = "Terminating"
            return self._record(name, seq)

    # -- Observed state (host-reported) -------------------------------------

    def report_observed(self, name: Any, observed: Any, seq: Any) -> ObservedState:
        """Record host-reported actual cluster state for a resource.

        Reporting ``observed=None`` means the object is gone from the cluster
        (used to confirm a planned deletion); anything else pins a digest.
        """
        seq = _check_seq(seq)
        name = _check_name(name)
        if observed is None:
            digest = None
        else:
            _canonical_or_raise(observed, "observed")
            digest = _digest(observed)
        with self._lock:
            entry = self._require_live(name)
            entry["observed_digest"] = digest
            return ObservedState(
                name=name, observed_digest=digest, audit_seq=seq
            )

    # -- Reconcile -----------------------------------------------------------

    def reconcile(self, seq: Any) -> ReconcileReport:
        """Level-triggered control loop: diff desired vs observed, plan actions."""
        seq = _check_seq(seq)
        with self._lock:
            self._reconcile_passes += 1
            actions: list[ReconcileAction] = []
            for name in sorted(self._resources):
                entry = self._resources[name]
                action = self._plan(entry)
                actions.append(action)
                self._apply_outcome(entry, action)
            # Purge resources whose deletion the host has confirmed.
            gone = [
                n
                for n, e in self._resources.items()
                if e["terminating"] and e["observed_digest"] is None
                and e.get("delete_planned")
            ]
            for n in gone:
                del self._resources[n]
            requeue = any(
                e["phase"] not in ("Ready",) for e in self._resources.values()
            )
            report = ReconcileReport(
                pass_seq=seq,
                actions=tuple(actions),
                requeue=requeue,
                digest=_digest(
                    [
                        {
                            "name": a.name,
                            "action": a.action,
                            "spec_digest": a.spec_digest,
                            "observed_digest": a.observed_digest,
                        }
                        for a in actions
                    ]
                ),
            )
            return report

    def _plan(self, entry: dict[str, Any]) -> ReconcileAction:
        name = entry["name"]
        spec_digest = entry["spec_digest"]
        observed = entry["observed_digest"]
        if entry["terminating"]:
            return ReconcileAction(
                name=name,
                action="delete",
                reason="deletion requested; finalizer clearing",
                spec_digest=spec_digest,
                observed_digest=observed,
            )
        if observed is None:
            return ReconcileAction(
                name=name,
                action="create",
                reason="no observed state; desired state absent from cluster",
                spec_digest=spec_digest,
                observed_digest=None,
            )
        if observed == spec_digest:
            return ReconcileAction(
                name=name,
                action="noop",
                reason="observed matches pinned spec digest",
                spec_digest=spec_digest,
                observed_digest=observed,
            )
        return ReconcileAction(
            name=name,
            action="update",
            reason="observed digest differs from pinned spec digest",
            spec_digest=spec_digest,
            observed_digest=observed,
        )

    def _apply_outcome(self, entry: dict[str, Any], action: ReconcileAction) -> None:
        if action.action == "noop":
            entry["phase"] = "Ready"
            entry["observed_generation"] = entry["generation"]
        elif action.action in ("create", "update"):
            entry["phase"] = "Progressing"
        elif action.action == "delete":
            entry["phase"] = "Terminating"
            entry["delete_planned"] = True

    # -- Views ----------------------------------------------------------------

    def status(self, name: Any) -> StatusRecord:
        """Current status view for a resource."""
        name = _check_name(name)
        with self._lock:
            entry = self._require_live(name)
            return StatusRecord(
                name=name,
                phase=entry["phase"],
                generation=entry["generation"],
                observed_generation=entry["observed_generation"],
                in_sync=entry["phase"] == "Ready"
                and entry["observed_generation"] == entry["generation"],
            )

    def names(self) -> tuple[str, ...]:
        """Managed resource names, sorted."""
        with self._lock:
            return tuple(sorted(self._resources))

    def reconcile_passes(self) -> int:
        """Number of reconcile passes run (monotone)."""
        with self._lock:
            return self._reconcile_passes

    # -- Internals --------------------------------------------------------------

    def _require_live(self, name: str) -> dict[str, Any]:
        try:
            return self._resources[name]
        except KeyError:
            raise UnknownResourceError(f"unknown resource {name!r}") from None

    def _record(self, name: str, seq: int) -> ResourceRecord:
        entry = self._resources[name]
        return ResourceRecord(
            name=name,
            crd=entry["kind"],
            spec_digest=entry["spec_digest"],
            generation=entry["generation"],
            phase=entry["phase"],
            audit_seq=seq,
        )


def k8s_operator_audit_event(
    kind: str, seq: Any, name: str | None = None, detail: Any = None
) -> dict[str, Any]:
    """Shape an operator event as an ``audit.ndjson/1``-style record."""
    seq = _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise K8sOperatorError(f"unknown audit kind: {kind!r}")
    record: dict[str, Any] = {
        "event": "k8s-operator",
        "kind": kind,
        "audit_seq": seq,
        "version": K8S_OPERATOR_VERSION,
        "schema": SCHEMA_PIN,
    }
    if name is not None:
        record["name"] = _check_name(name)
    if detail is not None:
        record["detail"] = detail
    return record


def main() -> None:
    """Self-check: CRD registry, apply, reconcile loop, deletion."""
    op = K8sOperator()
    crd = op.register_crd("example.com", "v1", "Widget", {"type": "object"}, 1)
    assert crd.crd_name == "widgets.example.com", crd.crd_name
    try:
        op.register_crd("example.com", "v1", "Widget", {}, 2)
        raise AssertionError("expected DuplicateCRDError")
    except DuplicateCRDError:
        pass
    try:
        op.apply("w1", "Gadget", {"replicas": 1}, 3)
        raise AssertionError("expected UnknownCRDError")
    except UnknownCRDError:
        pass
    rec = op.apply("w1", "Widget", {"replicas": 2}, 4)
    assert rec.phase == "Pending" and rec.generation == 1
    report = op.reconcile(5)
    assert report.actions[0].action == "create", report.actions
    assert op.status("w1").phase == "Progressing"
    # Host reports the created state back; loop converges.
    op.report_observed("w1", {"replicas": 2}, 6)
    report = op.reconcile(7)
    assert report.actions[0].action == "noop", report.actions
    st = op.status("w1")
    assert st.phase == "Ready" and st.in_sync, st
    assert report.requeue is False
    # Spec drift -> update action.
    op.update_spec("w1", {"replicas": 3}, 8)
    st = op.status("w1")
    assert st.phase == "Progressing" and st.generation == 2 and not st.in_sync
    report = op.reconcile(9)
    assert report.actions[0].action == "update", report.actions
    assert report.requeue is True
    # Deletion: terminating, plan emits delete, host confirms gone.
    op.delete("w1", 10)
    assert op.status("w1").phase == "Terminating"
    report = op.reconcile(11)
    assert report.actions[0].action == "delete", report.actions
    assert "w1" in op.names(), "still present until host confirms removal"
    # Host removes observed state -> resource leaves the registry.
    obs = op.report_observed("w1", None, 12)
    assert obs.observed_digest is None
    report = op.reconcile(13)
    assert op.names() == (), op.names()
    assert any(a.action == "delete" for a in report.actions), report.actions
    ev = k8s_operator_audit_event("reconciled", 14, "w1", {"actions": 0})
    assert ev["schema"] == SCHEMA_PIN and ev["version"] == K8S_OPERATOR_VERSION
    try:
        k8s_operator_audit_event("bogus", 15)
        raise AssertionError("expected K8sOperatorError")
    except K8sOperatorError:
        pass
    print("k8s-operator OK: CRD registry, reconcile loop, status, deletion")


if __name__ == "__main__":
    main()
