"""AI isolation: isolation -> verify decision ledger, Simulated.

Research note: AI isolation is the discipline of cutting a suspect,
compromised, or out-of-policy AI system off from the world - network
egress, APIs, shared resources, interactive sessions - so a fault,
exploit, or rogue behavior cannot propagate while humans or automated
controls assess it. This module is the *decision ledger* for declared
AI-isolation actions: which systems had which isolation kinds booked
(over a pinned isolation-kind vocabulary), what verdicts the host
declared against them, which follow-up isolations the host declared to
cover partial/failed attempts, and what isolation posture the ledger
derives - defensible bookkeeping, never proof that a system is really
isolated.

This module owns the isolate -> verify lifecycle:

* **isolate()** - book one declared isolation action (minted ``iso-N``
  ids; pinned isolation-kind vocabulary over the common isolation
  levers; pinned verdict vocabulary booked *as data*); host-reported
  severity is an int in [0,100]; the first isolation registers its
  system; raw evidence (packet captures, process lists, syscall traces,
  credentials) never enters records - digest pins only.
* **verify()** - **pure read**: re-derive one isolation record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the isolation really took effect.
* **evaluate()** - **pure read**: derive one system's isolation posture
  as data (``unisolated`` -> ``at-risk`` -> ``uncertain`` ->
  ``contained`` -> ``isolated``) with verdict tallies, a coverage count
  for partial/failed attempts followed by later isolations with verdict
  ``isolated``, and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``snapshot_isolation.py`` owns
MVCC *concurrency* snapshot isolation for agent state (transactions,
commits, first-committer-wins) - nothing to do with containing AI
systems; ``partition_manager.py`` owns range-shard bookkeeping
(split/merge/route) - likewise unrelated; ``ai_quarantine.py``-style
siblings do not exist in this tree; ``ai_defense.py`` / ``ai_resilience.py``
own defense-strengthening and resilience *assessment* ledgers - this
module is the AI-isolation *action* decision ledger none of them own:
declared isolation actions over the pinned isolation-kind vocabulary,
digest re-derivation, and the ledger-rule posture that turns declared
verdicts into an isolation claim, always as data, never as measured
truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-isolation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems,
executes no isolations, and proves nothing about real AI isolation. A
booked ``isolated`` verdict means "the host declared it", never "the
system is isolated". Packet captures, process lists, syscall traces,
credentials, session transcripts, and raw evidence never enter records
or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_ISOLATION_VERSION = "ai-isolation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-isolation.v1"

#: Pinned isolation-kind vocabulary (the isolation levers booked).
ISOLATION_KINDS = (
    "network-partition",
    "sandbox-containment",
    "process-quarantine",
    "resource-fence",
    "api-gateway-cutoff",
    "session-hold",
    "capability-revocation",
    "data-escrow",
)

#: Pinned isolation-verdict vocabulary (booked as data, never proof).
ISOLATE_VERDICTS = (
    "isolated",
    "partial",
    "failed",
    "inconclusive",
    "not-attempted",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unisolated",
    "at-risk",
    "uncertain",
    "contained",
    "isolated",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "isolated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "sample",
        "samples",
        "dataset",
        "example",
        "examples",
        "input",
        "inputs",
        "score",
        "scores",
        "metric",
        "metrics",
        "loss",
        "packet",
        "packets",
        "pcap",
        "network_flow",
        "network_traffic",
        "connection",
        "connections",
        "socket",
        "sockets",
        "firewall",
        "firewall_rules",
        "iptables",
        "endpoint",
        "endpoints",
        "ip",
        "ips",
        "address",
        "addresses",
        "hostname",
        "hostnames",
        "port",
        "ports",
        "url",
        "urls",
        "dns",
        "dns_query",
        "dns_queries",
        "process",
        "processes",
        "pid",
        "pids",
        "container",
        "containers",
        "namespace",
        "namespaces",
        "cgroup",
        "cgroups",
        "mount",
        "mounts",
        "filesystem",
        "syscall",
        "syscalls",
        "strace",
        "credential",
        "credentials",
        "token",
        "tokens",
        "api_key",
        "api_keys",
        "secret",
        "secrets",
        "auth",
        "authorization",
        "session",
        "sessions",
        "session_token",
        "cookie",
        "cookies",
        "header",
        "headers",
        "body",
        "payload",
        "payloads",
        "request",
        "requests",
        "user",
        "users",
        "chat",
        "chats",
        "message",
        "messages",
        "command",
        "commands",
        "capture",
        "captures",
        "evidence",
        "evidence_bundle",
        "file_contents",
        "files",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIIssolationError(Exception):
    """Base class for all ai-isolation ledger errors."""


class BadSystemError(AIIssolationError):
    pass


class UnknownSystemError(AIIssolationError):
    pass


class RetiredSystemError(AIIssolationError):
    pass


class BadIsolationKindError(AIIssolationError):
    pass


class BadVerdictError(AIIssolationError):
    pass


class BadSeverityError(AIIssolationError):
    pass


class BadDigestError(AIIssolationError):
    pass


class UnknownRecordError(AIIssolationError):
    pass


class BadReasonError(AIIssolationError):
    pass


class SeqOrderError(AIIssolationError):
    pass


class AuditKindError(AIIssolationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_isolation_kind(value: Any) -> str:
    if value not in ISOLATION_KINDS:
        raise BadIsolationKindError(
            f"isolation_kind must be one of {ISOLATION_KINDS}"
        )
    return value


def _check_verdict(value: Any) -> str:
    if value not in ISOLATE_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ISOLATE_VERDICTS}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IsolationRecord:
    isolation_id: str
    system_id: str
    seq: int
    isolation_kind: str
    verdict: str
    severity: int
    isolation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_isolate_payload(self), "ai-isolation.isolate")


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-isolation.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "ai-isolation.verify")


@dataclass(frozen=True)
class IsolationReport:
    system_id: str
    seq: int
    posture: str
    n_isolations: int
    n_isolated: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    n_not_attempted: int
    n_covered: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-isolation.evaluate"
        )


def _isolate_payload(rec: "IsolationRecord") -> Dict[str, Any]:
    return {
        "isolation_id": rec.isolation_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "isolation_kind": rec.isolation_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "isolation_digest": rec.isolation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "IsolationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_isolations": rep.n_isolations,
        "n_isolated": rep.n_isolated,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_attempted": rep.n_not_attempted,
        "n_covered": rep.n_covered,
        "integrity_ok": rep.integrity_ok,
    }


def ai_isolation_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIIssolationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-isolation",
        "version": AI_ISOLATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIIsolation:
    """AI-isolation action -> verify decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that a system is really isolated.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._isolations: Dict[str, IsolationRecord] = {}
        self._system_isolations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._isolation_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_isolation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-isolation",
                "version": AI_ISOLATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_isolation_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def isolate(
        self,
        system_id: str,
        seq: int,
        isolation_kind: str = "network-partition",
        verdict: str = "not-attempted",
        severity: int = 0,
        isolation_digest: str = "",
    ) -> IsolationRecord:
        """Book one declared isolation action (minted ``iso-N`` id).

        The first isolation on an id registers the system. Raw packet
        captures, process lists, syscall traces, and credentials never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-isolation.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                isolation_kind = _check_isolation_kind(isolation_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                isolation_digest = _check_digest(isolation_digest, "isolation_digest")
                self._require_live(system_id)
            except AIIssolationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._isolation_counter += 1
            isolation_id = f"iso-{self._isolation_counter}"
            provisional = IsolationRecord(
                isolation_id=isolation_id,
                system_id=system_id,
                seq=seq,
                isolation_kind=isolation_kind,
                verdict=verdict,
                severity=severity,
                isolation_digest=isolation_digest,
                digest="",
            )
            digest = _digest_pin(_isolate_payload(provisional), "ai-isolation.isolate")
            rec = IsolationRecord(
                isolation_id=isolation_id,
                system_id=system_id,
                seq=seq,
                isolation_kind=isolation_kind,
                verdict=verdict,
                severity=severity,
                isolation_digest=isolation_digest,
                digest=digest,
            )
            self._isolations[isolation_id] = rec
            self._system_isolations.setdefault(system_id, []).append(isolation_id)
            self._emit(
                "isolated",
                seq,
                isolation_id=isolation_id,
                system_id=system_id,
                isolation_kind=isolation_kind,
                verdict=verdict,
            )
            return rec

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """**Pure read**: re-derive one isolation record's digest pin.

        The seq is shape-validated but never consumed and no audit row
        is written. Verdict ``verified`` / ``tampered`` is booked as
        data; tamper is reported, never raised.
        """
        with self._lock:
            seq = _check_seq(seq)
            if record_id in self._isolations:
                rec = self._isolations[record_id]
            else:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            expected = _digest_pin(_isolate_payload(rec), "ai-isolation.isolate")
            integrity_ok = rec.digest == expected
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict="verified" if integrity_ok else "tampered",
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-isolation.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=provisional.verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> IsolationReport:
        """**Pure read**: derive one system's isolation posture as data.

        Posture precedence: ``at-risk`` (any open failed) ->
        ``uncertain`` (any inconclusive, or any open partial) ->
        ``unisolated`` (any not-attempted) -> ``contained`` (some
        failed/partial, all covered by later isolations with verdict
        ``isolated``) -> ``isolated`` (all isolated). A failed/partial
        isolation is *covered* only when a later isolation with verdict
        ``isolated`` exists for the same system - a follow-up that itself
        failed or was partial leaves the earlier attempt open. The seq
        is shape-validated, never consumed; no audit row is written.
        """
        with self._lock:
            system_id = _check_id(system_id, "system_id")
            seq = _check_seq(seq)
            if system_id not in self._system_isolations:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_isolations[system_id]
            recs = [self._isolations[i] for i in ids]
            n_isolations = len(recs)
            n_isolated = sum(1 for r in recs if r.verdict == "isolated")
            n_partial = sum(1 for r in recs if r.verdict == "partial")
            n_failed = sum(1 for r in recs if r.verdict == "failed")
            n_inconclusive = sum(1 for r in recs if r.verdict == "inconclusive")
            n_not_attempted = sum(1 for r in recs if r.verdict == "not-attempted")
            max_seq = max(r.seq for r in recs)
            later_isolated = {r.seq for r in recs if r.verdict == "isolated"}
            covered = {
                r.isolation_id
                for r in recs
                if r.verdict in ("partial", "failed")
                and any(s > r.seq for s in later_isolated)
            }
            n_covered = len(covered)
            open_failed = any(
                r.verdict == "failed" and r.isolation_id not in covered for r in recs
            )
            open_partial = any(
                r.verdict == "partial" and r.isolation_id not in covered for r in recs
            )
            any_inconclusive = n_inconclusive > 0
            if open_failed:
                posture = "at-risk"
            elif any_inconclusive or open_partial:
                posture = "uncertain"
            elif n_not_attempted > 0:
                posture = "unisolated"
            elif n_failed > 0 or n_partial > 0:
                posture = "contained"
            elif n_isolated == n_isolations and n_isolations > 0:
                posture = "isolated"
            else:
                posture = "contained"
            integrity_ok = all(
                r.digest == _digest_pin(_isolate_payload(r), "ai-isolation.isolate")
                for r in recs
            )
            provisional = IsolationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_isolations=n_isolations,
                n_isolated=n_isolated,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                n_not_attempted=n_not_attempted,
                n_covered=n_covered,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-isolation.evaluate")
            return IsolationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_isolations=n_isolations,
                n_isolated=n_isolated,
                n_partial=n_partial,
                n_failed=n_failed,
                n_inconclusive=n_inconclusive,
                n_not_attempted=n_not_attempted,
                n_covered=n_covered,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id. Ids are never recycled.

        Post-retire mutations are refused; reads still work.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_isolations:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                self._require_live(system_id)
            except AIIssolationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-isolation.retire")
            rec = RetireRecord(system_id=system_id, seq=seq, reason=reason, digest=digest)
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure-read views ---------------------------------------------------

    def isolation_record(self, isolation_id: str, seq: int) -> IsolationRecord:
        seq = _check_seq(seq)
        if isolation_id not in self._isolations:
            raise UnknownRecordError(f"unknown isolation: {isolation_id!r}")
        return self._isolations[isolation_id]

    def isolations_for(self, system_id: str, seq: int) -> List[IsolationRecord]:
        seq = _check_seq(seq)
        if system_id not in self._system_isolations:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return [self._isolations[i] for i in self._system_isolations[system_id]]

    def system_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._system_isolations)

    def isolation_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._isolations)

    def retired_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._retired)

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        return {
            "n_isolations": len(self._isolations),
            "n_systems": len(self._system_isolations),
            "n_retired": len(self._retired),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        _check_seq(seq)
        return list(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: book isolations, verify, and evaluate."""
    led = AIIsolation()
    rec = led.isolate("sys-1", 1, isolation_kind="sandbox-containment", verdict="failed")
    assert rec.isolation_id == "iso-1"
    assert rec.verify()
    rec2 = led.isolate("sys-1", 2, isolation_kind="network-partition", verdict="isolated")
    assert rec2.isolation_id == "iso-2"
    assert rec2.verify()
    vr = led.verify("iso-1", 3)
    assert vr.verdict == "verified"
    rep = led.evaluate("sys-1", 4)
    assert rep.posture == "contained"
    assert rep.n_covered == 1
    assert rep.verify()
    assert stdlib_only()
    print("ai-isolation OK: isolate, verify, evaluate, pins, audit")


if __name__ == "__main__":
    main()
