"""Automated alignment as a deterministic single-host decision ledger.

Research note: automated alignment is the governance loop around using
AI systems to do alignment work itself -- declared automation tasks over
a pinned task taxonomy (automated oversight, automated red-teaming,
eval generation, automated interpretability, monitoring,
reward-modeling), host-declared task executions with host-reported
outcomes, and ledger-derived alignment posture. This module is the
bookkeeping layer for that loop. It automates no alignment work,
runs no oversight, generates no evals, interprets no models, and
proves nothing about real-world alignment.

Distinct-layer rationale: ``scalable_oversight.py`` owns oversight
decomposition mechanics, ``human_oversight.py`` owns the human
assignment/review ledger, ``amplification.py`` owns the
amplify/distill loop, ``recursive_reward.py`` owns reward-model
decomposition -- this module is the *automated-alignment task*
decision ledger none of them own: declared automation tasks over the
pinned task vocabulary, declared executions with pinned outcomes, and
derived posture reports -- all booked as data, never evidence.

House style: frozen dataclasses, caller int seqs strictly increasing
with claim-then-burn (failed mutations consume their seq + book
``automated-alignment.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only +
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.

Honest scope: a booked ``misaligned`` outcome means "the host declared
the system misaligned on this execution", never that the system is
misaligned. A booked task performs no automation; ``verify()`` checks
record digests, never real alignment. ``report()`` derives posture
from the ledger; it never proves real-world alignment.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import hashlib
    import json

    def jcs_sha256_hex(obj) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


#: Module version.
AUTOMATED_ALIGNMENT_VERSION = "automated-alignment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.automated-alignment.v1"

#: Pinned automation-task vocabulary (declared tasks).
TASK_KINDS = (
    "oversight",
    "red-teaming",
    "eval-generation",
    "interpretability",
    "monitoring",
    "reward-modeling",
)

#: Pinned execution-outcome vocabulary. Outcomes are booked as data.
EXECUTION_OUTCOMES = (
    "aligned",
    "misaligned",
    "inconclusive",
    "not-run",
)

#: Pinned verification-verdict vocabulary. Verdicts are booked as data.
VERIFICATION_VERDICTS = (
    "verified",
    "unverified",
    "refuted",
    "inconclusive",
)

#: Pinned derived-posture vocabulary (ledger truth, never proof).
POSTURES = (
    "untasked",
    "misalignment-detected",
    "suspect",
    "inconclusive",
    "aligned",
)

#: Keys banned from audit details (raw alignment material must not cross).
_BANNED_AUDIT_KEYS = frozenset({
    "description", "text", "content", "details_raw", "notes",
    "evidence", "payload", "raw", "secret", "scenario",
    "transcript", "prompt", "response", "weights", "plan",
    "strategy", "trace", "goal", "task", "judgment",
})


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

class AutomatedAlignmentError(Exception):
    """Base error for automated-alignment misuse."""


class SeqOrderError(AutomatedAlignmentError):
    """Raised when a caller seq does not strictly increase."""


class BadIdError(AutomatedAlignmentError):
    """Raised on a malformed system, task, or execution id."""


class UnknownSystemError(AutomatedAlignmentError):
    """Raised when a system id has no booked rows (pure-read lookups)."""


class UnknownRecordError(AutomatedAlignmentError):
    """Raised when a task or execution id is unknown."""


class BadKindError(AutomatedAlignmentError):
    """Raised on a task kind outside the pinned vocabulary."""


class BadOutcomeError(AutomatedAlignmentError):
    """Raised on an execution outcome outside the pinned vocabulary."""


class BadVerdictError(AutomatedAlignmentError):
    """Raised on a verification verdict outside the pinned vocabulary."""


class BadDigestError(AutomatedAlignmentError):
    """Raised on a malformed sha256: digest pin."""


class DuplicateExecutionError(AutomatedAlignmentError):
    """Raised when an execution is already verified."""


class RetiredSystemError(AutomatedAlignmentError):
    """Raised when mutating a retired system id."""


class BadReasonError(AutomatedAlignmentError):
    """Raised on a retirement reason outside the pinned vocabulary."""


class AuditKindError(AutomatedAlignmentError):
    """Raised on an unknown audit kind or a banned audit key."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------

def _record_digest(body: dict) -> str:
    # The in-repo jcs_sha256_hex returns bare hex; pin it explicitly.
    return "sha256:" + jcs_sha256_hex(body)


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError("digest must be a str")
    if value and not (value.startswith("sha256:") and len(value) == 71):
        raise BadDigestError("digest must be a sha256: pin or ''")
    return value


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadIdError("id must be a non-empty str")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = ("manual", "superseded", "decommissioned", "completed")


def _check_reason(value: str) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"bad retire reason: {value!r}")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaskRecord:
    """One declared automated-alignment task for a system."""

    task_id: str
    system_id: str
    task_kind: str
    task_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "system_id": self.system_id,
            "task_kind": self.task_kind,
            "task_digest": self.task_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class ExecutionRecord:
    """One host-declared automated-alignment execution."""

    execution_id: str
    task_id: str
    system_id: str
    outcome: str
    execution_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "system_id": self.system_id,
            "outcome": self.outcome,
            "execution_digest": self.execution_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class VerificationRecord:
    """One declared verification of an automated-alignment execution."""

    verification_id: str
    execution_id: str
    task_id: str
    system_id: str
    verdict: str
    verification_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "verification_id": self.verification_id,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "system_id": self.system_id,
            "verdict": self.verdict,
            "verification_digest": self.verification_digest,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


@dataclass(frozen=True)
class AlignmentReport:
    """Derived automated-alignment posture report (pure read)."""

    seq: int
    system_id: str
    n_systems: int
    n_tasks: int
    n_executions: int
    n_verifications: int
    outcome_tallies: tuple
    verdict_tallies: tuple
    posture: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _record_digest(self.as_dict(include_digest=False))

    def as_dict(self, include_digest: bool = True) -> dict:
        d = {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "system_id": self.system_id,
            "n_systems": self.n_systems,
            "n_tasks": self.n_tasks,
            "n_executions": self.n_executions,
            "n_verifications": self.n_verifications,
            "outcome_tallies": [list(p) for p in self.outcome_tallies],
            "verdict_tallies": [list(p) for p in self.verdict_tallies],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
        }
        if include_digest:
            d["digest"] = self.digest
        return d


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "tasked",
    "executed",
    "verified",
    "retired",
    "automated-alignment.rejected",
)


def automated_alignment_audit_event(kind: str, details: dict) -> dict:
    """Build one ``audit.ndjson/1`` event. Raw alignment keys are banned."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(details, dict):
        raise AuditKindError("details must be a dict")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"raw alignment key banned from audit: {key!r}")
    return {"kind": "automated-alignment." + kind if "." not in kind else kind,
            "details": dict(details)}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class AutomatedAlignment:
    """Automated-alignment decision ledger: automate -> verify -> report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tasks: dict[str, TaskRecord] = {}
        self._task_ids: list[str] = []
        self._executions: dict[str, ExecutionRecord] = {}
        self._execution_ids: list[str] = []
        self._verifications: dict[str, VerificationRecord] = {}
        self._verification_ids: list[str] = []
        self._verified_executions: set[str] = set()
        self._retired: dict[str, RetireRecord] = {}
        self._audit: list[dict] = []
        self._n_rejected = 0

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: only stdlib imports (+ the in-repo sibling)."""
        import ast as _ast
        import pathlib as _pathlib
        allowed = {"__future__", "threading", "dataclasses", "hashlib",
                   "json", "typing", "canonical_json", "ast", "pathlib"}
        tree = _ast.parse(_pathlib.Path(__file__).read_text())
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, _ast.ImportFrom) and node.module:
                if node.module.split(".")[0] not in allowed:
                    return False
        return True

    # -- seq ------------------------------------------------------------
    def _claim(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, details: dict) -> None:
        self._audit.append(automated_alignment_audit_event(audit_kind, details))

    def _reject(self, seq: int, reason: str) -> None:
        self._n_rejected += 1
        self._emit("automated-alignment.rejected", {"seq": seq, "reason": reason})

    def _live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")

    # -- mutations ------------------------------------------------------
    def automate(self, system_id: str, seq: int,
                 task_kind: str = "oversight",
                 task_digest: str = "") -> TaskRecord:
        """Book one declared automated-alignment task (minted tsk-N).

        Books the *declaration*, never the automation's contents: raw
        alignment material travels as a ``sha256:`` pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id)
                self._live(system_id)
                if task_kind not in TASK_KINDS:
                    raise BadKindError(f"bad task kind: {task_kind!r}")
                _check_digest(task_digest)
                task_id = f"tsk-{len(self._task_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "task_id": task_id,
                    "system_id": system_id,
                    "task_kind": task_kind,
                    "task_digest": task_digest,
                    "seq": seq,
                }
                rec = TaskRecord(
                    task_id=task_id,
                    system_id=system_id,
                    task_kind=task_kind,
                    task_digest=task_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._tasks[task_id] = rec
                self._task_ids.append(task_id)
                self._emit("tasked", {
                    "task_id": task_id,
                    "system_id": system_id,
                    "task_kind": task_kind,
                    "seq": seq,
                })
                return rec
            except AutomatedAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def execute(self, task_id: str, seq: int,
                outcome: str = "aligned",
                execution_digest: str = "") -> ExecutionRecord:
        """Book one host-declared automated-alignment execution (minted exe-N).

        The outcome is booked *as data*: a ``misaligned`` outcome means the
        host declared the system misaligned on this execution, never that
        it is. Fail-closed on unknown or retired tasks.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(task_id)
                try:
                    task = self._tasks[task_id]
                except KeyError:
                    raise UnknownRecordError(f"unknown task: {task_id!r}")
                self._live(task.system_id)
                if outcome not in EXECUTION_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_digest(execution_digest)
                execution_id = f"exe-{len(self._execution_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "execution_id": execution_id,
                    "task_id": task_id,
                    "system_id": task.system_id,
                    "outcome": outcome,
                    "execution_digest": execution_digest,
                    "seq": seq,
                }
                rec = ExecutionRecord(
                    execution_id=execution_id,
                    task_id=task_id,
                    system_id=task.system_id,
                    outcome=outcome,
                    execution_digest=execution_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._executions[execution_id] = rec
                self._execution_ids.append(execution_id)
                self._emit("executed", {
                    "execution_id": execution_id,
                    "task_id": task_id,
                    "system_id": task.system_id,
                    "outcome": outcome,
                    "seq": seq,
                })
                return rec
            except AutomatedAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def verify(self, execution_id: str, seq: int,
               verdict: str = "verified",
               verification_digest: str = "") -> VerificationRecord:
        """Book one declared verification of an execution (minted vfy-N).

        The verdict is booked *as data*, never proof that any verification
        actually ran. One verification per execution.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(execution_id)
                try:
                    execution = self._executions[execution_id]
                except KeyError:
                    raise UnknownRecordError(
                        f"unknown execution: {execution_id!r}")
                self._live(execution.system_id)
                if verdict not in VERIFICATION_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                _check_digest(verification_digest)
                if execution_id in self._verified_executions:
                    raise DuplicateExecutionError(
                        f"execution already verified: {execution_id!r}")
                verification_id = f"vfy-{len(self._verification_ids) + 1}"
                body = {
                    "schema": SCHEMA_PIN,
                    "verification_id": verification_id,
                    "execution_id": execution_id,
                    "task_id": execution.task_id,
                    "system_id": execution.system_id,
                    "verdict": verdict,
                    "verification_digest": verification_digest,
                    "seq": seq,
                }
                rec = VerificationRecord(
                    verification_id=verification_id,
                    execution_id=execution_id,
                    task_id=execution.task_id,
                    system_id=execution.system_id,
                    verdict=verdict,
                    verification_digest=verification_digest,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._verifications[verification_id] = rec
                self._verification_ids.append(verification_id)
                self._verified_executions.add(execution_id)
                self._emit("verified", {
                    "verification_id": verification_id,
                    "execution_id": execution_id,
                    "task_id": execution.task_id,
                    "system_id": execution.system_id,
                    "verdict": verdict,
                    "seq": seq,
                })
                return rec
            except AutomatedAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    def retire(self, system_id: str, seq: int,
               reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id (ids never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id)
                _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}")
                body = {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "reason": reason,
                    "seq": seq,
                }
                rec = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_record_digest(body),
                )
                self._retired[system_id] = rec
                self._emit("retired", {
                    "system_id": system_id,
                    "reason": reason,
                    "seq": seq,
                })
                return rec
            except AutomatedAlignmentError as exc:
                self._reject(seq, type(exc).__name__)
                raise

    # -- pure-read views --------------------------------------------------
    def _view_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int")

    def _known_systems(self) -> set[str]:
        systems = {r.system_id for r in self._tasks.values()}
        systems |= {r.system_id for r in self._executions.values()}
        systems |= {r.system_id for r in self._verifications.values()}
        return systems

    def task_record(self, task_id: str, seq: int) -> TaskRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._tasks[task_id]
            except KeyError:
                raise UnknownRecordError(f"unknown task: {task_id!r}")

    def execution_record(self, execution_id: str, seq: int) -> ExecutionRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._executions[execution_id]
            except KeyError:
                raise UnknownRecordError(f"unknown execution: {execution_id!r}")

    def verification_record(self, verification_id: str,
                            seq: int) -> VerificationRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._verifications[verification_id]
            except KeyError:
                raise UnknownRecordError(
                    f"unknown verification: {verification_id!r}")

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._view_seq(seq)
            try:
                return self._retired[system_id]
            except KeyError:
                raise UnknownRecordError(f"unknown retired system: {system_id!r}")

    def tasks_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(t for t in self._task_ids
                         if self._tasks[t].system_id == system_id)

    def executions_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(e for e in self._execution_ids
                         if self._executions[e].system_id == system_id)

    def verifications_for(self, system_id: str, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(v for v in self._verification_ids
                         if self._verifications[v].system_id == system_id)

    def system_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._known_systems()))

    def retired_ids(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(sorted(self._retired))

    def report(self, seq: int, system_id: str = "") -> AlignmentReport:
        """Derive an automated-alignment posture report (pure read).

        ``system_id`` scopes to one system with booked rows; ``""``
        aggregates the whole ledger. Posture is ledger truth, never proof
        of real-world alignment:

        - ``untasked``: no tasks in scope
        - ``misalignment-detected``: any execution outcome ``misaligned``
          with a non-``refuted`` verification, or any unverified
          ``misaligned`` outcome
        - ``suspect``: any ``refuted`` verification or any
          ``inconclusive`` outcome
        - ``inconclusive``: any ``unverified`` verdict or ``inconclusive``
          verdict
        - ``aligned``: otherwise (all executions ``aligned`` and verified)

        ``integrity_ok`` re-derives every in-scope record digest and is
        reported as data, never raised.
        """
        with self._lock:
            self._view_seq(seq)
            if system_id:
                _check_id(system_id)
                if system_id not in self._known_systems():
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                tids = self.tasks_for(system_id, seq)
                eids = self.executions_for(system_id, seq)
                vids = self.verifications_for(system_id, seq)
                n_systems = 1
            else:
                tids = tuple(self._task_ids)
                eids = tuple(self._execution_ids)
                vids = tuple(self._verification_ids)
                n_systems = len(self._known_systems())
            outcome_tallies: dict[str, int] = {}
            verdict_tallies: dict[str, int] = {}
            refuted_executions: set[str] = set()
            for vid in vids:
                v = self._verifications[vid]
                verdict_tallies[v.verdict] = verdict_tallies.get(v.verdict, 0) + 1
                if v.verdict == "refuted":
                    refuted_executions.add(v.execution_id)
            for eid in eids:
                e = self._executions[eid]
                outcome_tallies[e.outcome] = outcome_tallies.get(e.outcome, 0) + 1
            integrity_ok = all(
                self._tasks[t].verify() for t in tids
            ) and all(
                self._executions[e].verify() for e in eids
            ) and all(
                self._verifications[v].verify() for v in vids
            )
            if not tids:
                posture = "untasked"
            elif outcome_tallies.get("misaligned", 0) > 0 and any(
                    self._executions[e].outcome == "misaligned"
                    and e not in refuted_executions for e in eids):
                posture = "misalignment-detected"
            elif verdict_tallies.get("refuted", 0) > 0 or \
                    outcome_tallies.get("inconclusive", 0) > 0:
                posture = "suspect"
            elif verdict_tallies.get("unverified", 0) > 0 or \
                    verdict_tallies.get("inconclusive", 0) > 0:
                posture = "inconclusive"
            else:
                posture = "aligned"
            outcome_tallies_t = tuple(sorted(outcome_tallies.items()))
            verdict_tallies_t = tuple(sorted(verdict_tallies.items()))
            body = {
                "schema": SCHEMA_PIN,
                "seq": seq,
                "system_id": system_id,
                "n_systems": n_systems,
                "n_tasks": len(tids),
                "n_executions": len(eids),
                "n_verifications": len(vids),
                "outcome_tallies": [list(p) for p in outcome_tallies_t],
                "verdict_tallies": [list(p) for p in verdict_tallies_t],
                "posture": posture,
                "integrity_ok": integrity_ok,
            }
            return AlignmentReport(
                seq=seq,
                system_id=system_id,
                n_systems=n_systems,
                n_tasks=len(tids),
                n_executions=len(eids),
                n_verifications=len(vids),
                outcome_tallies=outcome_tallies_t,
                verdict_tallies=verdict_tallies_t,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_record_digest(body),
            )

    def stats(self, seq: int) -> dict:
        with self._lock:
            self._view_seq(seq)
            return {
                "systems": len(self._known_systems()),
                "tasks": len(self._tasks),
                "executions": len(self._executions),
                "verifications": len(self._verifications),
                "retired": len(self._retired),
                "rejected": self._n_rejected,
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> tuple:
        with self._lock:
            self._view_seq(seq)
            return tuple(self._audit)


def main() -> None:
    a = AutomatedAlignment()
    t = a.automate("sys-1", 1, task_kind="oversight",
                   task_digest="sha256:" + "a" * 64)
    assert t.verify() and t.task_id == "tsk-1"
    e = a.execute("tsk-1", 2, outcome="aligned")
    assert e.verify() and e.execution_id == "exe-1"
    v = a.verify("exe-1", 3, verdict="verified")
    assert v.verify() and v.verification_id == "vfy-1"
    rep = a.report(4, "sys-1")
    assert rep.verify() and rep.posture == "aligned"
    assert rep.integrity_ok and rep.n_verifications == 1
    print("automated-alignment OK: automate, execute, verify, report, pins, audit")


if __name__ == "__main__":
    main()
