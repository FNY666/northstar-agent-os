"""Governed action runner: SAFR 4-gate orchestration with real components.

This is the production wiring that makes the governance stack cohere.
Not another ledger -- the thing that USES the ledgers to actually
govern actions.

Flow for one agent action::

    declare (SAFR) -> authorize (PermissionEngine) -> assess (Observer)
        -> audit (sealed ledger) -> execute (if all gates pass)

Each gate is fail-closed: a deny at any gate blocks execution and
seals the decision.  The SAFR checkpoint records the full 4-gate
trail; the sealed ledger provides forward integrity.

What this module IS: the orchestrator that drives real components
through the SAFR 4-gate model.

What this module IS NOT (honest scope):

* It does not implement the gates -- PermissionEngine, ObserverVerdictLedger,
  SafrCheckpoint, and ForwardSealLedger do.  This only orchestrates.
* The tool executor is host-provided (dependency injection).  In production
  this is the agent runtime's tool dispatcher, passed per call.
* The observer does not invent policy: its criteria are a pinned document
  (``DEFAULT_CRITERIA``), committed before authorization (Hubinger defense),
  and the verdict is computed from the gate decision plus a
  authorize-vs-assess argument-integrity check -- never a hardcoded allow.

Threading: one runner may serve concurrent calls (the runtime's parallel
tool path).  A re-entrant lock serializes the gate section (declare ->
authorize -> assess) so the shared SAFR/observer/ledger seq claims stay
ordered; the executor itself runs outside the lock so parallelism is
preserved.

House style: stdlib-only, no wall-clock, fail-closed, version/schema pins,
``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

#: Module version pin.  v2: real digests (no placeholder pins), the ledger
#: is actually sealed, the executor is per-call, seq handling is thread-safe.
GOVERNED_RUNNER_VERSION = "governed-action-runner.v2"

#: Schema pin.
SCHEMA_PIN = "northstar.governed-action-runner.v2"

#: The observer's pinned assessment criteria.  Committed (as a digest) before
#: authorization on every run, so the agent cannot adapt to the checks.
#: The policy: only gate-authorized actions run, and the arguments at assess
#: time must match the arguments at authorize time (TOCTOU tripwire).
DEFAULT_CRITERIA: Dict[str, Any] = {
    "observer": "northstar-production-governor",
    "policy": "gate-authorized-and-unchanged",
    "checks": [
        "the permission gate authorized this exact tool call",
        "the arguments at assess time match the arguments at authorize time",
    ],
    "version": "v1",
}


class GovernedRunnerError(Exception):
    """Fail-closed: any gate failure or malformed input raises."""


@dataclass(frozen=True)
class GovernedOutcome:
    """Result of a governed action run."""

    declaration_id: str
    executed: bool
    gate: str  # which gate decided: "authorize", "assess", "audit", "executed"
    decision: str  # "allow", "deny", "blocked"
    reason: str = ""
    #: The executor's return value when executed=True.  The runtime coerces
    #: it to a ToolResult; standalone hosts use it directly.
    result: Any = None
    #: Exception type name when the executor raised (e.g. "KeyError").
    #: The runtime maps it to the tool report's error_class, preserving
    #: the pre-runner behavior where handler failures kept their type.
    error_class: str = ""


class GovernedActionRunner:
    """Orchestrates SAFR 4-gate flow with real components.

    All components are dependency-injected (no sibling imports).
    The host wires real instances::

        runner = GovernedActionRunner(
            safr=SafrCheckpoint(),
            gate=PermissionEngine(audit_sink=sealed_sink),
            observer=ObserverVerdictLedger(),
            ledger=ForwardSealLedger(initial_key, checkpoint_key),
            executor=my_tool_dispatcher,  # or per-call in run()
        )
        outcome = runner.run(
            intent="agent-tool-call",
            action="Write",
            subject="main",
            tool="Write",
            tool_args={"path": "notes.txt", "content": "hi"},
            decision=production_gate_decision,  # skip re-evaluation
            authorized_inputs_digest=pin_at_authorize_time,
        )
    """

    def __init__(
        self,
        *,
        safr: Any,
        gate: Any,
        observer: Any,
        ledger: Any,
        executor: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        observer_id: str = "observer-1",
    ) -> None:
        for name, comp in (
            ("safr", safr),
            ("gate", gate),
            ("observer", observer),
            ("ledger", ledger),
        ):
            if comp is None:
                raise GovernedRunnerError(f"{name} is required")
        if executor is not None and not callable(executor):
            raise GovernedRunnerError("executor must be callable")
        self._safr = safr
        self._gate = gate
        self._observer = observer
        self._ledger = ledger
        self._executor = executor
        self._observer_id = observer_id
        self._seq = 0
        self._observer_seq = 0
        # RLock: run() holds it across the gate phase; _next_seq() also
        # takes it, and the executor runs outside it.
        self._lock = threading.RLock()

    def __getstate__(self) -> dict:
        """Support pickle (excludes the lock; components handle their own)."""
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict) -> None:
        """Restore after unpickle (recreates the lock)."""
        self.__dict__.update(state)
        self._lock = threading.RLock()

    @staticmethod
    def pin(obj: Any) -> str:
        """Canonical ``sha256:`` pin of ``obj``.

        Byte-identical encoding to ``permissions.digest_arguments`` for the
        same input, so a pin computed here compares equal to one computed
        there (the production authorize-vs-assess integrity check depends
        on this).
        """
        encoded = json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _next_observer_seq(self) -> int:
        with self._lock:
            self._observer_seq += 1
            return self._observer_seq

    def _seal(
        self,
        *,
        tool: str,
        subject: str,
        declaration_id: str,
        criteria_digest: str,
        args_pin: str,
        gate_decision: str,
        observer_verdict: str,
        outcome: str,
        reason: str,
    ) -> str:
        """Seal the 4-gate trail to the forward-seal ledger.

        Returns "" on success, or a ``[seal_failed:...]`` marker (mirroring
        the permission engine's audit-sink failure handling: visible, never
        fatal -- a broken seal chain must not crash the run, but it must
        not be silent either).
        """
        try:
            self._ledger.append(
                intent="governed-action",
                action=tool,
                subject=subject,
                authorization=f"gate:{gate_decision}",
                inputs_digest=args_pin,
                logic_digest=self.pin(
                    {
                        "declaration_id": declaration_id,
                        "criteria_digest": criteria_digest,
                        "observer_verdict": observer_verdict,
                    }
                ),
                execution_digest=self.pin({"outcome": outcome, "reason": reason}),
                outcome=outcome,
            )
        except Exception as error:  # noqa: BLE001 - seal failure is marked, not fatal
            return f" [seal_failed:{type(error).__name__}]"
        return ""

    def run(
        self,
        *,
        intent: str,
        action: str,
        subject: str,
        tool: str,
        tool_args: Optional[Dict[str, Any]] = None,
        inputs_digest: str = "",
        kind: Optional[str] = None,
        mutating: Optional[bool] = None,
        decision: Any = None,
        authorized_inputs_digest: str = "",
        criteria: Any = None,
        executor: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
    ) -> GovernedOutcome:
        """Run one governed action through all 4 gates.

        Returns GovernedOutcome.  Raises GovernedRunnerError on malformed
        input (fail-closed).  Gate denials return blocked outcomes, not
        exceptions -- the denial is the normal result.

        ``decision``: a pre-computed production authorization (duck-typed:
        ``.allowed`` and ``.reason``).  When given, the runner books it as
        the authorize gate instead of re-evaluating -- production already
        evaluated with full context, and evaluating twice would double-audit
        and double-ask the host.  When omitted, the runner authorizes through
        its own gate, passing the payload so argument-level policies fire.

        ``authorized_inputs_digest``: the args pin from authorize time.
        The assess gate denies when the assess-time args differ (TOCTOU
        tripwire).  Empty means "no separate authorize step" (standalone).

        ``criteria``: observer criteria document; defaults to
        ``DEFAULT_CRITERIA``.  Its digest is committed before authorization.

        ``executor``: per-call override for the constructor executor.
        """
        if not intent or not action or not subject or not tool:
            raise GovernedRunnerError("intent/action/subject/tool required")
        tool_args = dict(tool_args or {})
        run_executor = executor if executor is not None else self._executor
        if run_executor is None:
            raise GovernedRunnerError("executor is required")
        if not callable(run_executor):
            raise GovernedRunnerError("executor must be callable")

        args_pin = self.pin({"tool": tool, "args": tool_args})
        if not inputs_digest:
            inputs_digest = args_pin
        criteria_digest = self.pin(criteria if criteria is not None else DEFAULT_CRITERIA)

        # Gate 1: DECLARE (SAFR).  The lock makes the whole gate phase
        # (declare -> authorize -> assess) atomic across threads, so the
        # shared SAFR/observer seq claims stay ordered on the parallel path.
        with self._lock:
            seq = self._next_seq()
            declaration = self._safr.declare(seq, intent, action, subject, inputs_digest)
            decl_id = declaration.declaration_id

            # Observer pre-commits criteria BEFORE authorization (Hubinger).
            obs_seq = self._next_observer_seq()
            commitment = self._observer.commit_criteria(
                self._observer_id, obs_seq, criteria_digest
            )

            # Gate 2: AUTHORIZE (PermissionEngine)
            seq = self._next_seq()
            if decision is None:
                live = self._gate.evaluate(
                    tool, kind=kind, mutating=mutating, payload=dict(tool_args)
                )
                gate_decision = "allow" if live.allowed else "deny"
                gate_reason = live.reason or ""
            else:
                gate_decision = "allow" if decision.allowed else "deny"
                gate_reason = getattr(decision, "reason", "") or ""
            self._safr.authorize(seq, decl_id, gate_decision, "permission-engine", inputs_digest)
            if gate_decision == "deny":
                outcome: GovernedOutcome = GovernedOutcome(
                    declaration_id=decl_id,
                    executed=False,
                    gate="authorize",
                    decision="deny",
                    reason=gate_reason,
                )
                seal_note = self._seal(
                    tool=tool, subject=subject, declaration_id=decl_id,
                    criteria_digest=criteria_digest, args_pin=args_pin,
                    gate_decision=gate_decision, observer_verdict="-",
                    outcome="denied:authorize", reason=gate_reason,
                )
                if seal_note:
                    outcome = GovernedOutcome(
                        decl_id, False, "authorize", "deny", gate_reason + seal_note
                    )
                return outcome

            # Gate 3: ASSESS (Observer with pre-commitment).  Real check:
            # allow only if the gate allowed AND the arguments are unchanged
            # since authorize time.  Never a hardcoded allow.
            obs_seq = self._next_observer_seq()
            if authorized_inputs_digest and authorized_inputs_digest != args_pin:
                verdict = "deny"
                verdict_reason = "arguments changed between authorize and assess"
            else:
                verdict = "allow"
                verdict_reason = "gate authorized; arguments unchanged since authorize"
            action_digest = self.pin(
                {"tool": tool, "args": tool_args, "declaration_id": decl_id}
            )
            reason_digest = self.pin({"verdict": verdict, "reason": verdict_reason})
            verdict_rec = self._observer.verdict(
                self._observer_id,
                obs_seq,
                action_digest,
                verdict,
                reason_digest,
                commitment_id=commitment.commitment_id,
            )
            seq = self._next_seq()
            assess_result = "pass" if verdict_rec.verdict == "allow" else "fail"
            self._safr.assess(seq, decl_id, assess_result, inputs_digest)
            if assess_result == "fail":
                blocked_reason = f"observer verdict: {verdict_rec.verdict} ({verdict_reason})"
                outcome = GovernedOutcome(
                    declaration_id=decl_id,
                    executed=False,
                    gate="assess",
                    decision="blocked",
                    reason=blocked_reason,
                )
                seal_note = self._seal(
                    tool=tool, subject=subject, declaration_id=decl_id,
                    criteria_digest=criteria_digest, args_pin=args_pin,
                    gate_decision=gate_decision, observer_verdict=verdict,
                    outcome="denied:assess", reason=blocked_reason,
                )
                if seal_note:
                    outcome = GovernedOutcome(
                        decl_id, False, "assess", "blocked", blocked_reason + seal_note
                    )
                return outcome

        # Gate 4: EXECUTE (outside the lock -- parallelism preserved).
        try:
            result = run_executor(tool, tool_args)
        except Exception as error:  # noqa: BLE001 - a broken tool must not kill the run
            with self._lock:
                seq = self._next_seq()
                self._safr.audit(seq, decl_id, "aborted", inputs_digest)
                fail_reason = f"execution failed: {type(error).__name__}: {error}"
                seal_note = self._seal(
                    tool=tool, subject=subject, declaration_id=decl_id,
                    criteria_digest=criteria_digest, args_pin=args_pin,
                    gate_decision=gate_decision, observer_verdict=verdict,
                    outcome="aborted", reason=fail_reason,
                )
                return GovernedOutcome(
                    declaration_id=decl_id,
                    executed=False,
                    gate="audit",
                    decision="blocked",
                    reason=fail_reason + seal_note,
                    error_class=type(error).__name__,
                )

        with self._lock:
            seq = self._next_seq()
            self._safr.audit(seq, decl_id, "executed", inputs_digest)
            seal_note = self._seal(
                tool=tool, subject=subject, declaration_id=decl_id,
                criteria_digest=criteria_digest, args_pin=args_pin,
                gate_decision=gate_decision, observer_verdict=verdict,
                outcome="executed", reason="",
            )
            return GovernedOutcome(
                declaration_id=decl_id,
                executed=True,
                gate="executed",
                decision="allow",
                reason=seal_note.strip(),
                result=result,
            )


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "threading", "typing", "unittest"}
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
    """Self-check with stub components."""
    from unittest.mock import MagicMock

    safr = MagicMock()
    safr.declare.return_value.declaration_id = "safd-1"
    gate = MagicMock()
    gate.evaluate.return_value.allowed = True
    gate.evaluate.return_value.reason = ""
    observer = MagicMock()
    observer.commit_criteria.return_value.commitment_id = "obc-1"
    observer.verdict.return_value.verdict = "allow"
    ledger = MagicMock()
    executor = MagicMock(return_value="ok")

    runner = GovernedActionRunner(
        safr=safr, gate=gate, observer=observer, ledger=ledger, executor=executor
    )
    outcome = runner.run(
        intent="test", action="run", subject="svc", tool="my_tool", tool_args={}
    )
    assert outcome.executed is True
    assert outcome.gate == "executed"
    assert outcome.result == "ok"
    # Per-call executor override.
    outcome2 = runner.run(
        intent="test", action="run", subject="svc", tool="t2",
        executor=lambda t, a: "per-call",
    )
    assert outcome2.result == "per-call"
    # Real pins, not placeholders.
    assert runner.pin({"a": 1}) != "sha256:" + "00" * 32
    assert runner.pin({"a": 1}) == runner.pin({"a": 1})
    assert stdlib_only()
    print("governed-action-runner OK: 4-gate orchestration, stdlib")


if __name__ == "__main__":
    main()
