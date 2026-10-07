"""AI sandbox: declared sandbox-execution decision ledger, Simulated.

Research note: an AI sandbox is the execution-side complement of AI
isolation - a declared run of a declared AI artifact (model, agent,
tool, plugin, prompt pack, dataset, policy, workflow) inside a declared
sandbox profile (process jail, no-network, read-only filesystem,
cpu-quota, no-egress, container, vm, full isolation), and the outcome
the host declared it observed (clean, blocked, anomalous, inconclusive).
This module is the *decision ledger* for declared sandbox runs: which
artifacts had which runs booked (over a pinned artifact-kind
vocabulary and a pinned sandbox-profile vocabulary), what outcomes
were declared against them, and what sandbox posture the ledger derives
- defensible bookkeeping, never proof that any artifact was really
sandboxed.

This module owns the sandbox -> verify -> evaluate lifecycle:

* **sandbox()** - book one declared sandbox execution run (minted
  ``sbx-N`` ids; pinned artifact-kind and sandbox-profile vocabularies;
  pinned outcome vocabulary booked *as data*); the first run on an id
  registers the artifact; raw artifact material, weights, code,
  trajectories, snapshots, and tool outputs never enter records -
  digest pins only.
* **verify()** - **pure read**: re-derive one sandbox record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the run really happened.
* **evaluate()** - **pure read**: derive one artifact's sandbox posture
  as data (``untested`` -> ``compromised-suspect`` -> ``contested`` ->
  ``guarded`` -> ``clean``) with outcome tallies and a digest-pinned
  integrity flag.
* **retire()** - terminal retirement of an artifact id; ids are never
  recycled.

Distinct-layer rationale vs siblings: the safety-assessment /
mitigation ledgers (``ai_safety.py``) own assessment-to-mitigation
decisions; the incident ledgers (``ai_incident.py``) own incident
declaration/investigation; the recovery ledger (``ai_recovery.py``)
owns post-incident recovery actions - this module is the
*execution-ledger* none of them own: declared per-run sandbox
executions of declared artifacts against declared profiles, digest
re-derivation of those runs, and the ledger-rule posture that turns
declared runs into a sandbox claim, always as data, never as measured
containment.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-sandbox.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with
the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module executes nothing, sandboxes nothing,
contains nothing, and proves nothing about real-world execution
isolation. A booked ``clean`` posture means "the host declared it",
never "the artifact is safe"; a booked ``anomalous`` outcome means
"the host declared it", never "the artifact truly misbehaved".
Artifact material, weights, code, trajectories, tool outputs, prompts,
responses, checkpoints, and raw execution traces never enter records
or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_SANDBOX_VERSION = "ai-sandbox.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-sandbox.v1"

#: Pinned artifact-kind vocabulary (the kinds of declared artifacts).
ARTIFACT_KINDS = (
    "model",
    "agent",
    "tool",
    "plugin",
    "prompt-pack",
    "dataset",
    "policy",
    "workflow",
)

#: Pinned sandbox-profile vocabulary (the declared execution profiles).
SANDBOX_PROFILES = (
    "process-jail",
    "no-network",
    "read-only-fs",
    "cpu-quota",
    "no-egress",
    "container",
    "vm",
    "full-isolation",
)

#: Pinned run-outcome vocabulary (booked as data, never proof).
RUN_OUTCOMES = (
    "clean",
    "blocked",
    "anomalous",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "compromised-suspect",
    "contested",
    "guarded",
    "clean",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "sandboxed",
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
        "checkpoint_data",
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
        "restore_point",
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
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "incident_text",
        "incident_detail",
        "incident_description",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AISandboxError(Exception):
    """Base class for all ai-sandbox ledger errors."""


class BadArtifactError(AISandboxError):
    pass


class UnknownArtifactError(AISandboxError):
    pass


class RetiredArtifactError(AISandboxError):
    pass


class BadArtifactKindError(AISandboxError):
    pass


class BadSandboxProfileError(AISandboxError):
    pass


class BadOutcomeError(AISandboxError):
    pass


class BadDigestError(AISandboxError):
    pass


class BadReasonError(AISandboxError):
    pass


class UnknownSandboxError(AISandboxError):
    pass


class SeqOrderError(AISandboxError):
    pass


class AuditKindError(AISandboxError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadArtifactError(f"{what} must be a non-empty string")
    return value


def _check_artifact_kind(value: Any) -> str:
    if value not in ARTIFACT_KINDS:
        raise BadArtifactKindError(f"artifact_kind must be one of {ARTIFACT_KINDS}")
    return value


def _check_sandbox_profile(value: Any) -> str:
    if value not in SANDBOX_PROFILES:
        raise BadSandboxProfileError(
            f"sandbox_profile must be one of {SANDBOX_PROFILES}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in RUN_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {RUN_OUTCOMES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxRecord:
    sandbox_id: str
    artifact_id: str
    seq: int
    artifact_kind: str
    sandbox_profile: str
    outcome: str
    artifact_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _sandbox_payload(self), "ai-sandbox.sandbox"
        )


@dataclass(frozen=True)
class RetireRecord:
    artifact_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-sandbox.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-sandbox.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    artifact_id: str
    seq: int
    posture: str
    n_runs: int
    n_clean: int
    n_blocked: int
    n_anomalous: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-sandbox.evaluate"
        )


def _sandbox_payload(rec: "SandboxRecord") -> Dict[str, Any]:
    return {
        "sandbox_id": rec.sandbox_id,
        "artifact_id": rec.artifact_id,
        "seq": rec.seq,
        "artifact_kind": rec.artifact_kind,
        "sandbox_profile": rec.sandbox_profile,
        "outcome": rec.outcome,
        "artifact_digest": rec.artifact_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"artifact_id": rec.artifact_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "artifact_id": rep.artifact_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_runs": rep.n_runs,
        "n_clean": rep.n_clean,
        "n_blocked": rep.n_blocked,
        "n_anomalous": rep.n_anomalous,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_sandbox_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AISandboxError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-sandbox",
        "version": AI_SANDBOX_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AISandbox:
    """AI-sandbox declared-execution decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any artifact was really sandboxed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._runs: Dict[str, SandboxRecord] = {}
        self._artifact_runs: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._sandbox_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_sandbox_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-sandbox",
                "version": AI_SANDBOX_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_sandbox_audit_event(audit_kind, seq, **details))

    def _require_live(self, artifact_id: str) -> None:
        if artifact_id in self._retired:
            raise RetiredArtifactError(f"artifact is retired: {artifact_id!r}")

    # -- mutations ---------------------------------------------------------

    def sandbox(
        self,
        artifact_id: str,
        seq: int,
        artifact_kind: str = "model",
        sandbox_profile: str = "process-jail",
        outcome: str = "clean",
        artifact_digest: str = "",
    ) -> SandboxRecord:
        """Book one declared sandbox execution run (minted ``sbx-N`` id).

        The first run on an id registers the artifact. Raw artifact
        material, weights, code, trajectories, tool outputs, and traces
        never enter records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an ``ai-sandbox.rejected``
        row; rewinds raise bare.
        """
        with self._lock:
            try:
                artifact_id = _check_id(artifact_id, "artifact_id")
                self._require_seq(seq)
                artifact_kind = _check_artifact_kind(artifact_kind)
                sandbox_profile = _check_sandbox_profile(sandbox_profile)
                outcome = _check_outcome(outcome)
                artifact_digest = _check_digest(artifact_digest, "artifact_digest")
                self._require_live(artifact_id)
            except AISandboxError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._sandbox_counter += 1
            sandbox_id = f"sbx-{self._sandbox_counter}"
            provisional = SandboxRecord(
                sandbox_id=sandbox_id,
                artifact_id=artifact_id,
                seq=seq,
                artifact_kind=artifact_kind,
                sandbox_profile=sandbox_profile,
                outcome=outcome,
                artifact_digest=artifact_digest,
                digest="",
            )
            digest = _digest_pin(_sandbox_payload(provisional), "ai-sandbox.sandbox")
            rec = SandboxRecord(
                sandbox_id=sandbox_id,
                artifact_id=artifact_id,
                seq=seq,
                artifact_kind=artifact_kind,
                sandbox_profile=sandbox_profile,
                outcome=outcome,
                artifact_digest=artifact_digest,
                digest=digest,
            )
            self._runs[sandbox_id] = rec
            self._artifact_runs.setdefault(artifact_id, []).append(sandbox_id)
            self._emit(
                "sandboxed",
                seq,
                sandbox_id=sandbox_id,
                artifact_id=artifact_id,
                artifact_kind=artifact_kind,
                sandbox_profile=sandbox_profile,
                outcome=outcome,
                artifact_digest=artifact_digest,
            )
            return rec

    def retire(
        self, artifact_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of an artifact id; ids are never recycled."""
        with self._lock:
            try:
                artifact_id = _check_id(artifact_id, "artifact_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if artifact_id in self._retired:
                    raise RetiredArtifactError(
                        f"artifact is retired: {artifact_id!r}"
                    )
                if artifact_id not in self._artifact_runs:
                    raise UnknownArtifactError(
                        f"unknown artifact: {artifact_id!r}"
                    )
            except AISandboxError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                artifact_id=artifact_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-sandbox.retire")
            rec = RetireRecord(
                artifact_id=artifact_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[artifact_id] = rec
            self._emit("retired", seq, artifact_id=artifact_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, sandbox_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one sandbox record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the run really happened. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(sandbox_id, bool)
                or not isinstance(sandbox_id, str)
                or sandbox_id not in self._runs
            ):
                raise UnknownSandboxError(f"unknown sandbox id: {sandbox_id!r}")
            rec = self._runs[sandbox_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=sandbox_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-sandbox.verify")
            return VerificationReport(
                record_id=sandbox_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, artifact_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one artifact's sandbox posture as data.

        Posture by ledger rule: ``untested`` (nothing booked) ->
        ``compromised-suspect`` (any anomalous) -> ``contested`` (any
        inconclusive) -> ``guarded`` (any blocked) -> ``clean`` (all
        clean). ``integrity_ok`` re-derives all in-scope digest pins as
        data. Seq is shape-validated only - never consumed, no audit
        row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            artifact_id = _check_id(artifact_id, "artifact_id")
            if artifact_id not in self._artifact_runs:
                raise UnknownArtifactError(f"unknown artifact: {artifact_id!r}")
            ids = self._artifact_runs[artifact_id]
            recs = [self._runs[i] for i in ids]
            n_clean = sum(1 for r in recs if r.outcome == "clean")
            n_blocked = sum(1 for r in recs if r.outcome == "blocked")
            n_anomalous = sum(1 for r in recs if r.outcome == "anomalous")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            if n_anomalous:
                posture = "compromised-suspect"
            elif n_inconclusive:
                posture = "contested"
            elif n_blocked:
                posture = "guarded"
            elif n_clean and n_clean == len(recs):
                posture = "clean"
            else:
                posture = "untested"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                artifact_id=artifact_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_clean=n_clean,
                n_blocked=n_blocked,
                n_anomalous=n_anomalous,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-sandbox.evaluate")
            return EvaluationReport(
                artifact_id=artifact_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_clean=n_clean,
                n_blocked=n_blocked,
                n_anomalous=n_anomalous,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def sandbox_record(self, sandbox_id: str, seq: int) -> SandboxRecord:
        with self._lock:
            self._check_read_seq(seq)
            if sandbox_id not in self._runs:
                raise UnknownSandboxError(f"unknown sandbox id: {sandbox_id!r}")
            return self._runs[sandbox_id]

    def retire_record(self, artifact_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if artifact_id not in self._retired:
                raise UnknownArtifactError(f"unknown artifact: {artifact_id!r}")
            return self._retired[artifact_id]

    def sandboxes_for(self, artifact_id: str, seq: int) -> Tuple[SandboxRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._runs[i] for i in self._artifact_runs.get(artifact_id, [])
            )

    def artifact_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._artifact_runs))

    def sandbox_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._runs))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_artifacts": len(self._artifact_runs),
                "n_runs": len(self._runs),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_SANDBOX_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise sandbox -> verify -> evaluate."""
    ledger = AISandbox()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.sandbox(
        "artifact-1",
        1,
        artifact_kind="model",
        sandbox_profile="full-isolation",
        outcome="clean",
    )
    assert rec.verify()
    rep = ledger.verify(rec.sandbox_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("artifact-1", 3)
    assert ev.posture == "clean"
    ret = ledger.retire("artifact-1", 4)
    assert ret.verify()
    print("ai-sandbox OK: sandbox, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
