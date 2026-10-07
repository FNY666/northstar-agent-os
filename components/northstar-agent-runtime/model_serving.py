"""Model serving: KServe-shaped InferenceService lifecycle bookkeeping.

KServe (the Kubernetes model-inference platform) answers "which model
is *serving* right now, at what scale, and where did each prediction
request go?" -- the deployment-lifecycle half of ML operations:

* :meth:`ModelServing.deploy` books an ``InferenceService``-shaped
  serving deployment: a pinned model artifact digest (the same
  ``sha256:`` pins ``model_registry`` issues), a serving framework
  chosen from KServe's server vocabulary (``sklearn``/``xgboost``/
  ``tensorflow``/``pytorch``/``onnx``/``triton``/...), a replica
  budget, and a canary traffic percent (KServe's canary-rollout knob).
  Raw model URIs never enter a record -- URIs may carry credentials,
  so only the artifact *digest* is pinned. Status starts
  ``deploying``.
* :meth:`ModelServing.ready` books the Knative-revision readiness
  transition ``deploying -> ready``. A deployment that never reports
  ready never serves traffic: :meth:`ModelServing.predict` refuses
  fail-closed on non-ready services.
* :meth:`ModelServing.scale` books a declared replica-count change
  inside the deployment's ``[min_replicas, max_replicas]`` budget --
  the KServe KPA (Knative Pod Autoscaler) bookkeeping half. The count
  is a declaration, not proof the host ran that many pods.
* :meth:`ModelServing.predict` books one host-declared inference
  request routed to a *ready* deployment. The routing verdict
  (``routed``/``queued``/``dropped``) is data, never raised. Input
  payloads travel by digest only -- raw bytes never enter a record or
  cross the audit boundary.
* :meth:`ModelServing.undeploy` is terminal: the service id is retired
  and never recycled.

Deliberately distinct from the siblings:

* ``model_registry`` is the artifact *catalog* (which version is
  Production); this module is the *runtime deployment* (which service
  serves, at what scale, with what routing verdicts).
* ``secure_inference.predict`` *runs* a simulated model on sealed
  input; this module's ``predict`` books the *routing/ops decision* and
  never touches model code.

Honest scope: this is deployment bookkeeping, not an inference
engine. It cannot prove the host served the pinned digest (the host
holds the bytes), cannot prove replica counts match reality, and
cannot prove a ``routed`` request was answered. A quiet ledger means
"no known contract violation", never "the model is correct or fair".

Deterministic, no wall-clock (all caller-supplied int seqs), RLock
guarded, fail-closed, stdlib-only.

Version pin: model-serving.v1
Schema pin: northstar.model-serving.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


#: Module version.
MODEL_SERVING_VERSION = "model-serving.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.model-serving.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: KServe server vocabulary (built-in runtimes + custom).
FRAMEWORKS = (
    "sklearn",
    "xgboost",
    "lightgbm",
    "tensorflow",
    "pytorch",
    "onnx",
    "triton",
    "huggingface",
    "custom",
)

#: Deployment lifecycle states.
STATUS_DEPLOYING = "deploying"
STATUS_READY = "ready"
STATUS_UNDEPLOYED = "undeployed"
_STATUSES = frozenset({STATUS_DEPLOYING, STATUS_READY, STATUS_UNDEPLOYED})

#: Prediction routing verdicts (host-reported, as data).
OUTCOME_ROUTED = "routed"
OUTCOME_QUEUED = "queued"
OUTCOME_DROPPED = "dropped"
_OUTCOMES = frozenset({OUTCOME_ROUTED, OUTCOME_QUEUED, OUTCOME_DROPPED})

#: Undeploy reason vocabulary.
_UNDEPLOY_REASONS = frozenset(
    {"replaced", "rolled-back", "manual", "scaled-to-zero"}
)

#: Audit event kinds.
_KINDS = (
    "deployed",
    "ready",
    "scaled",
    "predicted",
    "undeployed",
    "rejected",
)

_MAX_ID_LEN = 256
_MAX_REPLICAS = 100000


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ModelServingError(Exception):
    """Base error for model-serving failures."""


class BadServiceError(ModelServingError):
    """A service id failed validation."""


class DuplicateServiceError(ModelServingError):
    """The service id is already deployed (active)."""


class RetiredServiceError(ModelServingError):
    """The service id was undeployed and is never recycled."""


class UnknownServiceError(ModelServingError):
    """No deployment is booked under this service id."""


class BadModelError(ModelServingError):
    """The model digest failed validation."""


class BadFrameworkError(ModelServingError):
    """The framework is not in the pinned vocabulary."""


class BadReplicaError(ModelServingError):
    """A replica count / budget failed validation."""


class BadCanaryError(ModelServingError):
    """The canary traffic percent failed validation."""


class BadOutcomeError(ModelServingError):
    """The prediction outcome is not in the pinned vocabulary."""


class BadReasonError(ModelServingError):
    """The undeploy reason is not in the pinned vocabulary."""


class ServiceStateError(ModelServingError):
    """The deployment is in a state that refuses this transition."""


class SeqOrderError(ModelServingError):
    """seq failed validation or did not strictly increase."""


class AuditKindError(ModelServingError):
    """Bad audit kind or banned key at the audit boundary."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _check_id(service_id: Any) -> str:
    if isinstance(service_id, bool) or not isinstance(service_id, str):
        raise BadServiceError(
            f"service_id must be a str, got {type(service_id).__name__}"
        )
    if not service_id:
        raise BadServiceError("service_id must not be empty")
    if len(service_id) > _MAX_ID_LEN:
        raise BadServiceError(f"service_id too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in service_id):
        raise BadServiceError("service_id must not contain whitespace")
    return service_id


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadModelError(f"digest must be a str, got {type(digest).__name__}")
    if not digest.startswith(_DIGEST_PREFIX):
        raise BadModelError("digest must be a 'sha256:' pin")
    hexpart = digest[len(_DIGEST_PREFIX):]
    if len(hexpart) != 64 or any(
        ch not in "0123456789abcdef" for ch in hexpart
    ):
        raise BadModelError("digest must be 'sha256:' + 64 lowercase hex")
    return digest


def _check_int(name: str, value: Any, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelServingError(f"{name} must be an int, got {type(value).__name__}")
    if not (lo <= value <= hi):
        raise ModelServingError(f"{name} must be in [{lo}, {hi}]")
    return value


def _pin(domain: str, *parts: Any) -> str:
    """Domain-separated ``sha256:`` pin over stringified parts."""
    material = "\x00".join(
        [MODEL_SERVING_VERSION, domain] + [str(p) for p in parts]
    )
    return _DIGEST_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def model_serving_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for model-serving.

    Raw URIs, payloads and model bytes never cross the audit boundary:
    ``detail`` may carry ids, digests, counts and verdicts -- never
    ``uri``/``payload``/``input``/``bytes``/``value``/``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {
        "uri",
        "model_uri",
        "payload",
        "input",
        "input_bytes",
        "bytes",
        "value",
        "raw",
        "model_bytes",
        "weights",
    }
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": MODEL_SERVING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentRecord:
    """A booked KServe-style InferenceService deployment."""

    service_id: str
    model_digest: str
    framework: str
    replicas: int
    min_replicas: int
    max_replicas: int
    canary_pct: int
    status: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the pin; False means tampered."""
        return self.digest == _pin(
            "deployment",
            self.service_id,
            self.model_digest,
            self.framework,
            self.replicas,
            self.min_replicas,
            self.max_replicas,
            self.canary_pct,
            self.status,
            self.seq,
        )


@dataclass(frozen=True)
class ReadyRecord:
    """The ``deploying -> ready`` readiness booking."""

    service_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin("ready", self.service_id, self.seq)


@dataclass(frozen=True)
class ScaleRecord:
    """A declared replica-count change."""

    service_id: str
    old_replicas: int
    new_replicas: int
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "scale", self.service_id, self.old_replicas, self.new_replicas, self.seq
        )


@dataclass(frozen=True)
class PredictionRecord:
    """One host-declared inference request routed to a deployment."""

    pred_id: str
    service_id: str
    input_digest: str
    outcome: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "predict",
            self.pred_id,
            self.service_id,
            self.input_digest,
            self.outcome,
            self.seq,
        )


@dataclass(frozen=True)
class UndeployRecord:
    """The terminal undeploy booking."""

    service_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "undeploy", self.service_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class ServiceState:
    """Pure read view of a deployment's current state."""

    service_id: str
    model_digest: str
    framework: str
    replicas: int
    min_replicas: int
    max_replicas: int
    canary_pct: int
    status: str
    deployed_seq: int
    state_digest: str

    def verify(self) -> bool:
        return self.state_digest == _pin(
            "service-state",
            self.service_id,
            self.model_digest,
            self.framework,
            self.replicas,
            self.min_replicas,
            self.max_replicas,
            self.canary_pct,
            self.status,
            self.deployed_seq,
        )


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ModelServing:
    """KServe-shaped serving-deployment lifecycle as a deterministic ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # service_id -> mutable dict holding the deployment state
        self._services: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        self._preds: Dict[str, PredictionRecord] = {}
        self._pred_n = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internal -----------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase (last {self._seq})"
            )
        self._seq = seq
        return seq

    def _reject(self, seq: int, error: ModelServingError, **detail: Any) -> None:
        row = model_serving_audit_event(
            "rejected", {"error": type(error).__name__, **detail}, seq
        )
        self._audit.append(row)
        raise error

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(model_serving_audit_event(kind, detail, seq))

    def _active(self, service_id: str, seq: int) -> Dict[str, Any]:
        try:
            return self._services[service_id]
        except KeyError:
            if service_id in self._retired:
                self._reject(seq, RetiredServiceError(service_id), service_id=service_id)
            self._reject(seq, UnknownServiceError(service_id), service_id=service_id)
            raise  # unreachable; _reject always raises

    # -- mutations ----------------------------------------------------------

    def deploy(
        self,
        service_id: str,
        model_digest: str,
        seq: int,
        framework: str = "custom",
        replicas: int = 1,
        min_replicas: int = 1,
        max_replicas: int = 1,
        canary_pct: int = 0,
    ) -> DeploymentRecord:
        """Book a serving deployment; returns a frozen ``DeploymentRecord``.

        Status starts ``deploying``. The model artifact travels by
        ``sha256:`` digest only -- raw URIs are never accepted (they may
        carry credentials).
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                service_id = _check_id(service_id)
                model_digest = _check_digest(model_digest)
                if not isinstance(framework, str) or framework not in FRAMEWORKS:
                    raise BadFrameworkError(
                        f"framework must be one of {FRAMEWORKS}, got {framework!r}"
                    )
                try:
                    min_replicas = _check_int("min_replicas", min_replicas, 1, _MAX_REPLICAS)
                    max_replicas = _check_int("max_replicas", max_replicas, 1, _MAX_REPLICAS)
                    replicas = _check_int("replicas", replicas, 1, _MAX_REPLICAS)
                except ModelServingError as exc:
                    raise BadReplicaError(str(exc)) from exc
                if min_replicas > max_replicas:
                    raise BadReplicaError("min_replicas must be <= max_replicas")
                if not (min_replicas <= replicas <= max_replicas):
                    raise BadReplicaError(
                        "replicas must be within [min_replicas, max_replicas]"
                    )
                try:
                    canary_pct = _check_int("canary_pct", canary_pct, 0, 100)
                except ModelServingError as exc:
                    raise BadCanaryError(str(exc)) from exc
                if service_id in self._retired:
                    raise RetiredServiceError(service_id)
                if service_id in self._services:
                    raise DuplicateServiceError(service_id)
            except ModelServingError as exc:
                self._reject(seq, exc, service_id=str(service_id))
            digest = _pin(
                "deployment",
                service_id,
                model_digest,
                framework,
                replicas,
                min_replicas,
                max_replicas,
                canary_pct,
                STATUS_DEPLOYING,
                seq,
            )
            record = DeploymentRecord(
                service_id=service_id,
                model_digest=model_digest,
                framework=framework,
                replicas=replicas,
                min_replicas=min_replicas,
                max_replicas=max_replicas,
                canary_pct=canary_pct,
                status=STATUS_DEPLOYING,
                seq=seq,
                digest=digest,
            )
            self._services[service_id] = {
                "record": record,
                "status": STATUS_DEPLOYING,
                "replicas": replicas,
                "min_replicas": min_replicas,
                "max_replicas": max_replicas,
                "deployed_seq": seq,
            }
            self._emit(
                "deployed",
                {
                    "service_id": service_id,
                    "model_digest": model_digest,
                    "framework": framework,
                    "replicas": replicas,
                    "canary_pct": canary_pct,
                },
                seq,
            )
            return record

    def ready(self, service_id: str, seq: int) -> ReadyRecord:
        """Book the ``deploying -> ready`` readiness transition."""
        with self._lock:
            seq = self._claim(seq)
            try:
                service_id = _check_id(service_id)
                svc = self._active(service_id, seq)
                if svc["status"] != STATUS_DEPLOYING:
                    raise ServiceStateError(
                        f"{service_id} is {svc['status']}, not deploying"
                    )
            except ModelServingError as exc:
                self._reject(seq, exc, service_id=str(service_id))
            svc["status"] = STATUS_READY
            record = ReadyRecord(
                service_id=service_id,
                seq=seq,
                digest=_pin("ready", service_id, seq),
            )
            self._emit("ready", {"service_id": service_id}, seq)
            return record

    def scale(self, service_id: str, replicas: int, seq: int) -> ScaleRecord:
        """Book a declared replica-count change inside the budget."""
        with self._lock:
            seq = self._claim(seq)
            try:
                service_id = _check_id(service_id)
                svc = self._active(service_id, seq)
                try:
                    replicas = _check_int("replicas", replicas, 1, _MAX_REPLICAS)
                except ModelServingError as exc:
                    raise BadReplicaError(str(exc)) from exc
                if not (svc["min_replicas"] <= replicas <= svc["max_replicas"]):
                    raise BadReplicaError(
                        "replicas must be within [min_replicas, max_replicas]"
                    )
            except ModelServingError as exc:
                self._reject(seq, exc, service_id=str(service_id))
            old = svc["replicas"]
            svc["replicas"] = replicas
            record = ScaleRecord(
                service_id=service_id,
                old_replicas=old,
                new_replicas=replicas,
                seq=seq,
                digest=_pin("scale", service_id, old, replicas, seq),
            )
            self._emit(
                "scaled",
                {
                    "service_id": service_id,
                    "old_replicas": old,
                    "new_replicas": replicas,
                },
                seq,
            )
            return record

    def predict(
        self,
        service_id: str,
        seq: int,
        input_digest: str = "",
        outcome: str = OUTCOME_ROUTED,
    ) -> PredictionRecord:
        """Book one inference request routed to a *ready* deployment.

        The outcome (``routed``/``queued``/``dropped``) is host-reported
        data. This never runs model code -- see ``secure_inference``
        for the execution-simulation half.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                service_id = _check_id(service_id)
                svc = self._active(service_id, seq)
                if svc["status"] != STATUS_READY:
                    raise ServiceStateError(
                        f"{service_id} is {svc['status']}, not ready"
                    )
                if input_digest != "" and not isinstance(input_digest, str):
                    raise BadModelError("input_digest must be a str")
                if input_digest != "":
                    try:
                        input_digest = _check_digest(input_digest)
                    except BadModelError as exc:
                        raise BadModelError(
                            f"input_digest: {exc}"
                        ) from exc
                if not isinstance(outcome, str) or outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}, got {outcome!r}"
                    )
            except ModelServingError as exc:
                self._reject(seq, exc, service_id=str(service_id))
            self._pred_n += 1
            pred_id = f"pred-{self._pred_n}"
            record = PredictionRecord(
                pred_id=pred_id,
                service_id=service_id,
                input_digest=input_digest,
                outcome=outcome,
                seq=seq,
                digest=_pin(
                    "predict", pred_id, service_id, input_digest, outcome, seq
                ),
            )
            self._preds[pred_id] = record
            self._emit(
                "predicted",
                {
                    "pred_id": pred_id,
                    "service_id": service_id,
                    "outcome": outcome,
                },
                seq,
            )
            return record

    def undeploy(
        self, service_id: str, seq: int, reason: str = "manual"
    ) -> UndeployRecord:
        """Terminal undeploy; the service id is retired forever."""
        with self._lock:
            seq = self._claim(seq)
            try:
                service_id = _check_id(service_id)
                self._active(service_id, seq)
                if not isinstance(reason, str) or reason not in _UNDEPLOY_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_UNDEPLOY_REASONS)}, "
                        f"got {reason!r}"
                    )
            except ModelServingError as exc:
                self._reject(seq, exc, service_id=str(service_id))
            del self._services[service_id]
            self._retired.add(service_id)
            record = UndeployRecord(
                service_id=service_id,
                reason=reason,
                seq=seq,
                digest=_pin("undeploy", service_id, reason, seq),
            )
            self._emit(
                "undeployed", {"service_id": service_id, "reason": reason}, seq
            )
            return record

    # -- pure read views ----------------------------------------------------

    def service(self, service_id: str, seq: int) -> ServiceState:
        """Pure read view of a deployment's current state."""
        with self._lock:
            _check_seq(seq)
            service_id = _check_id(service_id)
            if service_id in self._retired:
                raise RetiredServiceError(service_id)
            try:
                svc = self._services[service_id]
            except KeyError:
                raise UnknownServiceError(service_id)
            rec = svc["record"]
            state = ServiceState(
                service_id=service_id,
                model_digest=rec.model_digest,
                framework=rec.framework,
                replicas=svc["replicas"],
                min_replicas=svc["min_replicas"],
                max_replicas=svc["max_replicas"],
                canary_pct=rec.canary_pct,
                status=svc["status"],
                deployed_seq=svc["deployed_seq"],
                state_digest="",
            )
            return ServiceState(
                **{**state.__dict__, "state_digest": _pin(
                    "service-state",
                    service_id,
                    rec.model_digest,
                    rec.framework,
                    svc["replicas"],
                    svc["min_replicas"],
                    svc["max_replicas"],
                    rec.canary_pct,
                    svc["status"],
                    svc["deployed_seq"],
                )}
            )

    def service_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted active service ids; pure read."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._services))

    def prediction(self, pred_id: str, seq: int) -> PredictionRecord:
        """Fetch one booked prediction; pure read."""
        with self._lock:
            _check_seq(seq)
            try:
                return self._preds[pred_id]
            except KeyError:
                raise UnknownServiceError(f"unknown prediction {pred_id!r}")

    def stats(self, seq: int) -> Dict[str, int]:
        """Pure read counters."""
        with self._lock:
            _check_seq(seq)
            return {
                "active_services": len(self._services),
                "retired_services": len(self._retired),
                "predictions": len(self._preds),
                "audit_rows": len(self._audit),
                "last_seq": self._seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        """Return a copy of the audit rows."""
        with self._lock:
            return list(self._audit)


def main() -> None:
    """Self-check: deploy, ready, scale, predict, undeploy, audit."""
    ms = ModelServing()
    digest = _DIGEST_PREFIX + "ab" * 32
    dep = ms.deploy(
        "svc-1",
        digest,
        1,
        framework="sklearn",
        replicas=1,
        min_replicas=1,
        max_replicas=4,
        canary_pct=10,
    )
    assert dep.verify()
    assert ms.service("svc-1", 1).status == STATUS_DEPLOYING
    try:
        ms.predict("svc-1", 2)
        raise AssertionError("predict before ready must fail")
    except ServiceStateError:
        pass
    rdy = ms.ready("svc-1", 3)
    assert rdy.verify()
    scl = ms.scale("svc-1", 3, 4)
    assert scl.verify() and scl.new_replicas == 3
    pred = ms.predict("svc-1", 5, input_digest=digest)
    assert pred.verify() and pred.outcome == OUTCOME_ROUTED
    und = ms.undeploy("svc-1", 6, reason="replaced")
    assert und.verify()
    assert ms.stats(6)["retired_services"] == 1
    print("model-serving OK: deploy, ready, scale, predict, undeploy, pins, audit")


if __name__ == "__main__":
    main()
