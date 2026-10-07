"""Edge-function deploy/invoke bookkeeping: a ledger for edge compute decisions.

An ``EdgeCompute`` books host-reported edge-function deployment and
invocation decisions as a deterministic single-host state machine:

- ``deploy(function_id, seq, name, runtime, memory_mb, entry_digest,
  regions=())`` pins a function definition. Runtime and region choices come
  from pinned vocabularies (Cloudflare-Workers/Lambda@Edge shaped); memory
  comes from a pinned allowance table; the entry bundle is booked by digest
  only (``sha256:`` + 64 hex), never by content. Duplicate ids refused.
- ``invoke(function_id, seq, input_digest, region=None, cold=False)`` books
  one invocation as a frozen ``InvocationRecord`` (``inv-N`` ids). The
  outcome is produced by a host-injectable
  ``executor(function, input_digest, attempt, cold) -> str`` (default:
  deterministic in-memory simulator). A failed invocation is *data*
  (``status="failed"``), never raised; a raising executor counts as failure
  (fail-closed).
- ``retry_invocation(invocation_id, seq)`` books a follow-up attempt linked
  via ``prev_invocation_id``; retrying a delivered invocation raises
  ``AlreadyDeliveredError``; exceeding ``MAX_ATTEMPTS`` raises
  ``MaxAttemptsError``.
- ``undeploy(function_id, seq)`` books a terminal ``UndeployRecord``;
  invocations after undeploy raise ``DeactivatedError``.
- ``logs(function_id, seq, since_seq=0, limit=100)`` is a pure read view
  (seq validated, not consumed) returning a frozen ``LogPage`` of the
  function's booked invocation history.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``edge-compute.v1``,
schema pin ``northstar.edge-compute.v1``, ``main()`` self-check.

Honest scope: this module books *deployment and invocation decisions*,
not compute — there is no edge network, no sandbox, no real cold-start
scheduler. The default executor is a stub; a host executor reports its own
truth (GIGO). Output digests are booked as digests; payload bytes never
enter records or the audit boundary.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
EDGE_COMPUTE_VERSION = "edge-compute.v1"

#: Schema pin carried by records and audit events.
EDGE_COMPUTE_SCHEMA = "northstar.edge-compute.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pin: invocation statuses.
STATUSES = ("delivered", "failed", "pending")

#: Pin: maximum invocation attempts per invocation chain.
MAX_ATTEMPTS = 5

#: Pin: supported edge runtimes (Cloudflare-Workers/Lambda@Edge shaped).
RUNTIMES = ("python", "javascript", "typescript", "wasm")

#: Pin: allowed memory allowances in MB.
MEMORY_ALLOWANCES = (64, 128, 256, 512)

#: Pin: edge region vocabulary (a curated subset, IATA-shaped codes).
REGIONS = ("iad", "sfo", "lhr", "fra", "nrt", "sin", "syd", "gru")

#: Pin: function lifecycle states.
FUNCTION_STATES = ("active", "undeployed")

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class EdgeComputeError(Exception):
    """Base class for all edge_compute errors."""


class UnknownFunctionError(EdgeComputeError):
    """The referenced function id is not deployed."""


class DuplicateFunctionError(EdgeComputeError):
    """A function with this id is already deployed."""


class BadDeployError(EdgeComputeError):
    """The deployment request is malformed (runtime, memory, digest, region)."""


class UnknownInvocationError(EdgeComputeError):
    """The referenced invocation id is unknown."""


class AlreadyDeliveredError(EdgeComputeError):
    """Retrying an invocation whose final attempt already delivered."""


class MaxAttemptsError(EdgeComputeError):
    """The invocation chain already exhausted MAX_ATTEMPTS attempts."""


class DeactivatedError(EdgeComputeError):
    """Invoking a function that has been undeployed."""


class BadInvocationError(EdgeComputeError):
    """The invocation request is malformed (digest, region)."""


class SeqOrderError(EdgeComputeError):
    """Seq is not a non-negative int or not strictly increasing."""


class AuditKindError(EdgeComputeError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _tag_encode(value: Any) -> Any:
    if value is True:
        return {"$bool": True}
    if value is False:
        return {"$bool": False}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadDeployError("integer out of safe range")
        return {"$int": value}
    if isinstance(value, float):
        raise BadDeployError("floats are not permitted in pinned structures")
    if isinstance(value, (list, tuple)):
        return [_tag_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _tag_encode(v) for k, v in value.items()}
    if isinstance(value, (str, type(None))):
        return value
    raise BadDeployError(f"unsupported value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    canonical = jcs_canonical_json(_tag_encode(list(parts)))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _check_digest(digest: Any) -> None:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise BadDeployError("digest must look like 'sha256:' + 64 hex chars")
    if not _HEX64_RE.match(digest[len("sha256:"):]):
        raise BadDeployError("digest must look like 'sha256:' + 64 hex chars")


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "function-deployed",
    "function-undeployed",
    "invoked",
    "failed",
    "retried",
    "rejected",
)


def edge_compute_audit_event(
    kind: str,
    seq: int,
    function_id: str = "",
    invocation_id: str = "",
    detail: str = "",
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; ids and digest pins only."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": EDGE_COMPUTE_VERSION,
        "kind": kind,
        "seq": seq,
        "function_id": function_id,
        "invocation_id": invocation_id,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeploymentRecord:
    function_id: str
    name: str
    runtime: str
    memory_mb: int
    entry_digest: str
    regions: Tuple[str, ...]
    seq: int
    state: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            EDGE_COMPUTE_SCHEMA,
            "deployment",
            self.function_id,
            self.name,
            self.runtime,
            self.memory_mb,
            self.entry_digest,
            self.regions,
            self.seq,
            self.state,
        )


@dataclass(frozen=True)
class UndeployRecord:
    function_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            EDGE_COMPUTE_SCHEMA,
            "undeploy",
            self.function_id,
            self.seq,
            self.reason,
        )


@dataclass(frozen=True)
class InvocationRecord:
    invocation_id: str
    function_id: str
    input_digest: str
    region: str
    cold: bool
    attempt: int
    status: str
    output_digest: str
    seq: int
    prev_invocation_id: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            EDGE_COMPUTE_SCHEMA,
            "invocation",
            self.invocation_id,
            self.function_id,
            self.input_digest,
            self.region,
            self.cold,
            self.attempt,
            self.status,
            self.output_digest,
            self.seq,
            self.prev_invocation_id,
        )


@dataclass(frozen=True)
class LogEntry:
    invocation_id: str
    status: str
    region: str
    attempt: int
    seq: int


@dataclass(frozen=True)
class LogPage:
    function_id: str
    entries: Tuple[LogEntry, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            EDGE_COMPUTE_SCHEMA,
            "log-page",
            self.function_id,
            self.seq,
            [(e.invocation_id, e.status, e.region, e.attempt, e.seq) for e in self.entries],
        )


# ---------------------------------------------------------------------------
# EdgeCompute
# ---------------------------------------------------------------------------


def _default_executor(
    function: DeploymentRecord,
    input_digest: str,
    attempt: int,
    cold: bool,
) -> str:
    """Deterministic in-memory stub: books a derived output digest, no I/O."""
    return _pin("edge-compute-sim", function.function_id, input_digest, attempt, cold)


class EdgeCompute:
    """Deterministic single-host ledger for edge-function decisions."""

    def __init__(
        self,
        seed: str = "default",
        executor: Optional[
            Callable[[DeploymentRecord, str, int, bool], str]
        ] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._executor = executor or _default_executor
        self._functions: Dict[str, DeploymentRecord] = {}
        self._invocations: Dict[str, InvocationRecord] = {}
        self._chains: Dict[str, List[str]] = {}  # root invocation id -> attempt ids
        self._undeploys: Dict[str, UndeployRecord] = {}
        self._last_seq = -1
        self._f_counter = 0
        self._i_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _check_seq(self, seq: Any) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq

    def _reject(self, seq: int, reason: str) -> None:
        try:
            self._check_seq(seq)
        except SeqOrderError:
            pass
        self._audit.append(
            edge_compute_audit_event("rejected", seq, detail=reason)
        )

    def _salt(self) -> str:
        return _pin(EDGE_COMPUTE_SCHEMA, "output-salt", self._seed)

    def _next_invocation_id(self) -> str:
        self._i_counter += 1
        return f"inv-{self._i_counter}"

    # -- public API -----------------------------------------------------

    def deploy(
        self,
        function_id: str,
        seq: int,
        name: str,
        runtime: str,
        memory_mb: int,
        entry_digest: str,
        regions: Sequence[str] = (),
    ) -> DeploymentRecord:
        with self._lock:
            if not isinstance(function_id, str) or not function_id:
                self._reject(seq, "bad-function-id")
                raise BadDeployError("function_id must be a non-empty str")
            if function_id in self._functions:
                self._reject(seq, "duplicate-function")
                raise DuplicateFunctionError(f"function already deployed: {function_id!r}")
            if not isinstance(name, str) or not name or len(name) > 128:
                self._reject(seq, "bad-name")
                raise BadDeployError("name must be a non-empty str (<=128 chars)")
            if runtime not in RUNTIMES:
                self._reject(seq, "bad-runtime")
                raise BadDeployError(f"runtime must be one of {RUNTIMES}")
            if memory_mb not in MEMORY_ALLOWANCES:
                self._reject(seq, "bad-memory")
                raise BadDeployError(f"memory_mb must be one of {MEMORY_ALLOWANCES}")
            try:
                _check_digest(entry_digest)
            except BadDeployError:
                self._reject(seq, "bad-digest")
                raise
            norm_regions = tuple(regions)
            for r in norm_regions:
                if r not in REGIONS:
                    self._reject(seq, "bad-region")
                    raise BadDeployError(f"unknown region: {r!r}")
            self._check_seq(seq)
            record = DeploymentRecord(
                function_id=function_id,
                name=name,
                runtime=runtime,
                memory_mb=memory_mb,
                entry_digest=entry_digest,
                regions=norm_regions,
                seq=seq,
                state="active",
                digest=_pin(
                    EDGE_COMPUTE_SCHEMA,
                    "deployment",
                    function_id,
                    name,
                    runtime,
                    memory_mb,
                    entry_digest,
                    norm_regions,
                    seq,
                    "active",
                ),
            )
            self._functions[function_id] = record
            self._audit.append(
                edge_compute_audit_event(
                    "function-deployed", seq, function_id=function_id
                )
            )
            return record

    def undeploy(self, function_id: str, seq: int, reason: str = "") -> UndeployRecord:
        with self._lock:
            if function_id not in self._functions:
                self._reject(seq, "unknown-function")
                raise UnknownFunctionError(f"unknown function: {function_id!r}")
            if function_id in self._undeploys:
                self._reject(seq, "already-undeployed")
                raise DeactivatedError(f"function already undeployed: {function_id!r}")
            if not isinstance(reason, str) or len(reason) > 512:
                self._reject(seq, "bad-reason")
                raise BadDeployError("reason must be a str (<=512 chars)")
            self._check_seq(seq)
            record = UndeployRecord(
                function_id=function_id,
                seq=seq,
                reason=reason,
                digest=_pin(EDGE_COMPUTE_SCHEMA, "undeploy", function_id, seq, reason),
            )
            self._undeploys[function_id] = record
            self._functions[function_id] = DeploymentRecord(
                function_id=self._functions[function_id].function_id,
                name=self._functions[function_id].name,
                runtime=self._functions[function_id].runtime,
                memory_mb=self._functions[function_id].memory_mb,
                entry_digest=self._functions[function_id].entry_digest,
                regions=self._functions[function_id].regions,
                seq=self._functions[function_id].seq,
                state="undeployed",
                digest=_pin(
                    EDGE_COMPUTE_SCHEMA,
                    "deployment",
                    function_id,
                    self._functions[function_id].name,
                    self._functions[function_id].runtime,
                    self._functions[function_id].memory_mb,
                    self._functions[function_id].entry_digest,
                    self._functions[function_id].regions,
                    self._functions[function_id].seq,
                    "undeployed",
                ),
            )
            self._audit.append(
                edge_compute_audit_event(
                    "function-undeployed", seq, function_id=function_id, detail=reason
                )
            )
            return record

    def invoke(
        self,
        function_id: str,
        seq: int,
        input_digest: str,
        region: Optional[str] = None,
        cold: bool = False,
    ) -> InvocationRecord:
        with self._lock:
            if function_id not in self._functions:
                self._reject(seq, "unknown-function")
                raise UnknownFunctionError(f"unknown function: {function_id!r}")
            if function_id in self._undeploys:
                self._reject(seq, "deactivated")
                raise DeactivatedError(f"function is undeployed: {function_id!r}")
            fn = self._functions[function_id]
            try:
                _check_digest(input_digest)
            except BadDeployError:
                self._reject(seq, "bad-digest")
                raise BadInvocationError("input_digest must be a sha256 digest pin")
            if region is None:
                region = fn.regions[0] if fn.regions else "iad"
            if region not in REGIONS:
                self._reject(seq, "bad-region")
                raise BadInvocationError(f"unknown region: {region!r}")
            if fn.regions and region not in fn.regions:
                self._reject(seq, "region-not-deployed")
                raise BadInvocationError(
                    f"region {region!r} not in function's deployed regions"
                )
            if not isinstance(cold, bool):
                self._reject(seq, "bad-cold")
                raise BadInvocationError("cold must be a bool")
            self._check_seq(seq)
            invocation_id = self._next_invocation_id()
            try:
                output_digest = self._executor(fn, input_digest, 1, cold)
            except Exception:
                output_digest = ""
                status = "failed"
            else:
                if not isinstance(output_digest, str) or not output_digest:
                    status = "failed"
                    output_digest = ""
                else:
                    status = "delivered"
            record = InvocationRecord(
                invocation_id=invocation_id,
                function_id=function_id,
                input_digest=input_digest,
                region=region,
                cold=cold,
                attempt=1,
                status=status,
                output_digest=output_digest,
                seq=seq,
                prev_invocation_id="",
                digest=_pin(
                    EDGE_COMPUTE_SCHEMA,
                    "invocation",
                    invocation_id,
                    function_id,
                    input_digest,
                    region,
                    cold,
                    1,
                    status,
                    output_digest,
                    seq,
                    "",
                ),
            )
            self._invocations[invocation_id] = record
            self._chains[invocation_id] = [invocation_id]
            self._audit.append(
                edge_compute_audit_event(
                    "invoked" if status == "delivered" else "failed",
                    seq,
                    function_id=function_id,
                    invocation_id=invocation_id,
                    detail=f"attempt=1 region={region} cold={cold}",
                )
            )
            return record

    def retry_invocation(self, invocation_id: str, seq: int) -> InvocationRecord:
        with self._lock:
            if invocation_id not in self._invocations:
                self._reject(seq, "unknown-invocation")
                raise UnknownInvocationError(
                    f"unknown invocation: {invocation_id!r}"
                )
            prior = self._invocations[invocation_id]
            root_id = self._root_of(invocation_id)
            chain = self._chains[root_id]
            if prior.status == "delivered":
                self._reject(seq, "already-delivered")
                raise AlreadyDeliveredError(
                    f"invocation already delivered: {invocation_id!r}"
                )
            if len(chain) >= MAX_ATTEMPTS:
                self._reject(seq, "max-attempts")
                raise MaxAttemptsError(
                    f"invocation chain exhausted {MAX_ATTEMPTS} attempts"
                )
            fn = self._functions[prior.function_id]
            attempt = prior.attempt + 1
            self._check_seq(seq)
            new_id = self._next_invocation_id()
            try:
                output_digest = self._executor(fn, prior.input_digest, attempt, prior.cold)
            except Exception:
                output_digest = ""
                status = "failed"
            else:
                if not isinstance(output_digest, str) or not output_digest:
                    status = "failed"
                    output_digest = ""
                else:
                    status = "delivered"
            record = InvocationRecord(
                invocation_id=new_id,
                function_id=prior.function_id,
                input_digest=prior.input_digest,
                region=prior.region,
                cold=prior.cold,
                attempt=attempt,
                status=status,
                output_digest=output_digest,
                seq=seq,
                prev_invocation_id=invocation_id,
                digest=_pin(
                    EDGE_COMPUTE_SCHEMA,
                    "invocation",
                    new_id,
                    prior.function_id,
                    prior.input_digest,
                    prior.region,
                    prior.cold,
                    attempt,
                    status,
                    output_digest,
                    seq,
                    invocation_id,
                ),
            )
            self._invocations[new_id] = record
            chain.append(new_id)
            self._audit.append(
                edge_compute_audit_event(
                    "retried",
                    seq,
                    function_id=prior.function_id,
                    invocation_id=new_id,
                    detail=f"attempt={attempt} prev={invocation_id}",
                )
            )
            return record

    def logs(
        self,
        function_id: str,
        seq: int,
        since_seq: int = 0,
        limit: int = 100,
    ) -> LogPage:
        with self._lock:
            if function_id not in self._functions:
                raise UnknownFunctionError(f"unknown function: {function_id!r}")
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
                raise SeqOrderError("seq must be a non-negative int")
            if (
                not isinstance(since_seq, int)
                or isinstance(since_seq, bool)
                or since_seq < 0
            ):
                raise BadDeployError("since_seq must be a non-negative int")
            if (
                not isinstance(limit, int)
                or isinstance(limit, bool)
                or limit < 1
                or limit > 1000
            ):
                raise BadDeployError("limit must be an int in [1, 1000]")
            entries = tuple(
                LogEntry(
                    invocation_id=inv.invocation_id,
                    status=inv.status,
                    region=inv.region,
                    attempt=inv.attempt,
                    seq=inv.seq,
                )
                for inv in sorted(
                    (
                        inv
                        for inv in self._invocations.values()
                        if inv.function_id == function_id and inv.seq > since_seq
                    ),
                    key=lambda inv: inv.seq,
                )[:limit]
            )
            return LogPage(
                function_id=function_id,
                entries=entries,
                seq=seq,
                digest=_pin(
                    EDGE_COMPUTE_SCHEMA,
                    "log-page",
                    function_id,
                    seq,
                    [
                        (e.invocation_id, e.status, e.region, e.attempt, e.seq)
                        for e in entries
                    ],
                ),
            )

    # -- views ----------------------------------------------------------

    def _root_of(self, invocation_id: str) -> str:
        prior = self._invocations[invocation_id]
        while prior.prev_invocation_id:
            prior = self._invocations[prior.prev_invocation_id]
        return prior.invocation_id

    def function(self, function_id: str) -> DeploymentRecord:
        if function_id not in self._functions:
            raise UnknownFunctionError(f"unknown function: {function_id!r}")
        return self._functions[function_id]

    def invocation(self, invocation_id: str) -> InvocationRecord:
        if invocation_id not in self._invocations:
            raise UnknownInvocationError(f"unknown invocation: {invocation_id!r}")
        return self._invocations[invocation_id]

    def undeploy_record(self, function_id: str) -> UndeployRecord:
        if function_id not in self._undeploys:
            raise UnknownFunctionError(f"function not undeployed: {function_id!r}")
        return self._undeploys[function_id]

    def function_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._functions))

    def invocation_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._invocations))

    def attempts_for(self, root_invocation_id: str) -> Tuple[str, ...]:
        return tuple(self._chains.get(root_invocation_id, ()))

    def stats(self) -> Dict[str, int]:
        delivered = sum(1 for i in self._invocations.values() if i.status == "delivered")
        failed = sum(1 for i in self._invocations.values() if i.status == "failed")
        return {
            "functions": len(self._functions),
            "invocations": len(self._invocations),
            "delivered": delivered,
            "failed": failed,
            "undeployed": len(self._undeploys),
        }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    def fail_first(
        function: DeploymentRecord, input_digest: str, attempt: int, cold: bool
    ) -> str:
        if attempt == 1:
            raise RuntimeError("simulated cold-start failure")
        return _pin("selfcheck", function.function_id, input_digest, attempt)

    mgr = EdgeCompute(seed="selfcheck", executor=fail_first)
    digest = "sha256:" + "ab" * 32
    fn = mgr.deploy(
        "fn-1", 1, "resize", "python", 128, digest, regions=("iad", "sfo")
    )
    assert fn.verify() and fn.state == "active"
    assert fn.runtime == "python" and fn.memory_mb == 128
    r1 = mgr.invoke("fn-1", 2, digest, region="iad", cold=True)
    assert r1.status == "failed" and r1.attempt == 1, r1
    assert r1.verify()
    r2 = mgr.retry_invocation(r1.invocation_id, 3)
    assert r2.status == "delivered", r2
    assert r2.attempt == 2 and r2.prev_invocation_id == r1.invocation_id
    assert r2.verify()
    assert mgr.attempts_for(r1.invocation_id) == (r1.invocation_id, r2.invocation_id)
    try:
        mgr.retry_invocation(r2.invocation_id, 4)
    except AlreadyDeliveredError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected AlreadyDeliveredError")
    page = mgr.logs("fn-1", 5)
    assert page.verify() and len(page.entries) == 2
    u = mgr.undeploy("fn-1", 6, "replaced by fn-2")
    assert u.verify()
    try:
        mgr.invoke("fn-1", 7, digest)
    except DeactivatedError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DeactivatedError")
    # cross-instance determinism of the default executor
    a = EdgeCompute(seed="x")
    b = EdgeCompute(seed="x")
    da = a.deploy("g", 1, "n", "wasm", 64, digest)
    db = b.deploy("g", 1, "n", "wasm", 64, digest)
    assert da.digest == db.digest
    ra = a.invoke("g", 2, digest)
    rb = b.invoke("g", 2, digest)
    assert ra.output_digest == rb.output_digest and ra.output_digest != ""
    print("edge-compute OK: deploy, invoke, retry, logs, undeploy, pins, audit")


if __name__ == "__main__":
    main()
