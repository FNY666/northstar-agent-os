"""Iterative Distillation and Amplification (IDA) decision ledger, Simulated.

Research note: IDA (Christiano's proposal) trains an aligned base agent
``M_0`` (e.g. imitation learning on human behavior), then iterates
``M_{t+1} = Distill(Amp(M_t))``: an amplification operator ``Amp`` combines
many copies of the current agent (e.g. Humans-Consulting-HCH question
decomposition, recursive consultation, parallel ensembles), and a
distillation step trains a successor on the amplified system's behavior. If
each distillation preserves alignment, the sequence stays competitive and
aligned; if a distillation slips, the whole chain inherits the slip. The
dangerous half of an IDA step is the raw material: weight tensors, rollout
traces, consultation transcripts, teacher/student logits. Those must never
be bundled with the bookkeeping record that tracks the iteration.

This module is that bookkeeping layer. It:

* **amplify()** - book one declared amplification (minted ``amp-N`` ids) over
  a pinned amplification-kind vocabulary; the first amplification on an id
  registers the agent at generation 0; raw teacher/rollout material travels
  as ``sha256:`` digest pins only.
* **distill()** - book one declared distillation (minted ``dst-N`` ids) of a
  booked amplification into a fresh successor agent at generation parent+1,
  over a pinned strategy vocabulary; the declared alignment verdict
  (``aligned`` / ``misaligned`` / ``uncertain`` / ``not-evaluated``) is data,
  never proof the distillation preserved alignment (or didn't).
* **iterate()** - pure-read derived IDA trajectory posture per agent (or the
  whole ledger), as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``ida.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``aligned`` is a host-declared claim, never proof a
real distillation preserved alignment; a booked ``misaligned`` is a
host-declared claim, never proof a real model went bad; an
``aligned-chain`` posture means the ledger's rule was satisfied, never that
the agents in the chain are actually safe; no amplification is performed
and no model is trained here.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
IDA_VERSION = "ida.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ida.v1"

#: Pinned amplification-kind vocabulary (declared, never proof real copies ran).
AMP_KINDS = (
    "hch-decomposition",
    "recursive-consultation",
    "parallel-ensemble",
    "deliberative-debate",
    "tree-search-consult",
    "tool-augmented-amp",
    "simulated-oversight",
    "iterative-refinement",
)

#: Pinned distillation-strategy vocabulary (declared, never proof of a real
#: distillation step).
DISTILL_STRATEGIES = (
    "imitation-learning",
    "rl-distillation",
    "model-compression",
    "consultation-distillation",
    "preference-distillation",
    "debate-distillation",
    "oversight-distillation",
    "reward-ensemble",
)

#: Pinned distillation-verdict vocabulary (declared, never measured truth).
DISTILL_VERDICTS = (
    "aligned",
    "misaligned",
    "uncertain",
    "not-evaluated",
)

#: Pinned derived postures for iterate().
POSTURES = (
    "unstarted",
    "diverged",
    "uncertain",
    "aligned-chain",
    "unevaluated",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "amplified",
    "distilled",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "activations",
        "gradients",
        "rollouts",
        "transcripts",
        "prompts",
        "responses",
        "evidence",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "secret",
        "details",
        "detail",
        "description",
        "model",
        "teacher",
        "student",
        "logits",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class IDAError(Exception):
    """Base error for IDA-ledger misuse."""


class BadIdError(IDAError):
    """Malformed agent / amplification / distillation id."""


class BadDigestError(IDAError):
    """Malformed sha256: digest pin."""


class BadKindError(IDAError):
    """Amplification kind outside the pinned vocabulary."""


class BadStrategyError(IDAError):
    """Distillation strategy outside the pinned vocabulary."""


class BadVerdictError(IDAError):
    """Distillation verdict outside the pinned vocabulary."""


class UnknownAgentError(IDAError):
    """Reference to an agent id that was never registered."""


class UnknownAmplificationError(IDAError):
    """Reference to an amplification id that was never booked."""


class DuplicateSuccessorError(IDAError):
    """Successor id is already a registered agent."""


class SelfDistillError(IDAError):
    """Successor id is identical to the parent agent id."""


class AlreadyDistilledError(IDAError):
    """This amplification was already distilled into a successor."""


class SeqOrderError(IDAError):
    """Caller seq did not strictly increase."""


class AuditKindError(IDAError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AmplificationRecord:
    """One declared amplification of an agent (minted amp-N ids)."""

    amplification_id: str
    agent_id: str
    generation: int
    amp_kind: str
    agent_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "amplification_id": self.amplification_id,
            "agent_id": self.agent_id,
            "generation": self.generation,
            "amp_kind": self.amp_kind,
            "agent_digest": self.agent_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "amplification_id": self.amplification_id,
                "agent_id": self.agent_id,
                "generation": self.generation,
                "amp_kind": self.amp_kind,
                "agent_digest": self.agent_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class DistillationRecord:
    """One declared distillation into a successor agent (minted dst-N ids)."""

    distillation_id: str
    amplification_id: str
    parent_id: str
    successor_id: str
    generation: int
    strategy: str
    verdict: str
    plan_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "distillation_id": self.distillation_id,
            "amplification_id": self.amplification_id,
            "parent_id": self.parent_id,
            "successor_id": self.successor_id,
            "generation": self.generation,
            "strategy": self.strategy,
            "verdict": self.verdict,
            "plan_digest": self.plan_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "distillation_id": self.distillation_id,
                "amplification_id": self.amplification_id,
                "parent_id": self.parent_id,
                "successor_id": self.successor_id,
                "generation": self.generation,
                "strategy": self.strategy,
                "verdict": self.verdict,
                "plan_digest": self.plan_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class IterationReport:
    """Derived IDA trajectory posture (pure read, as data)."""

    agent_id: str
    scoped: bool
    n_agents: int
    n_amplifications: int
    n_distillations: int
    max_generation: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "agent_id": self.agent_id,
            "scoped": self.scoped,
            "n_agents": self.n_agents,
            "n_amplifications": self.n_amplifications,
            "n_distillations": self.n_distillations,
            "max_generation": self.max_generation,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "agent_id": self.agent_id,
                "scoped": self.scoped,
                "n_agents": self.n_agents,
                "n_amplifications": self.n_amplifications,
                "n_distillations": self.n_distillations,
                "max_generation": self.max_generation,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def ida_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the IDA ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class IDA:
    """IDA decision ledger (Simulated).

    ``amplify()`` / ``distill()`` mutate the ledger and consume caller seqs;
    ``iterate()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._amplifications: Dict[str, AmplificationRecord] = {}
        self._agent_amplifications: Dict[str, List[str]] = {}
        self._generations: Dict[str, int] = {}
        self._distillations: Dict[str, DistillationRecord] = {}
        self._amplification_distillation: Dict[str, str] = {}
        self._amp_counter = 0
        self._dst_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ida_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ida_audit_event(audit_kind, seq, **details))

    def _register(self, agent_id: str, generation: int) -> None:
        if agent_id not in self._generations:
            self._generations[agent_id] = generation

    # -- amplify --------------------------------------------------------------

    def amplify(
        self,
        agent_id: str,
        seq: int,
        amp_kind: str = "hch-decomposition",
        agent_digest: str = "",
    ) -> AmplificationRecord:
        """Book one declared amplification of an agent.

        The first amplification on an id registers the agent at generation
        0; raw teacher/rollout material never enters records (digest pins
        only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(agent_id, "agent_id")
                if amp_kind not in AMP_KINDS:
                    raise BadKindError(f"bad amp kind: {amp_kind!r}")
                agent_digest = _require_optional_digest(
                    agent_digest, "agent_digest"
                )
                self._register(agent_id, 0)
                generation = self._generations[agent_id]
                self._amp_counter += 1
                amplification_id = f"amp-{self._amp_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "amplification_id": amplification_id,
                        "agent_id": agent_id,
                        "generation": generation,
                        "amp_kind": amp_kind,
                        "agent_digest": agent_digest,
                        "seq": seq,
                    }
                )
                record = AmplificationRecord(
                    amplification_id=amplification_id,
                    agent_id=agent_id,
                    generation=generation,
                    amp_kind=amp_kind,
                    agent_digest=agent_digest,
                    seq=seq,
                    digest=digest,
                )
                self._amplifications[amplification_id] = record
                self._agent_amplifications.setdefault(agent_id, []).append(
                    amplification_id
                )
                self._emit(
                    "amplified",
                    seq,
                    amplification_id=amplification_id,
                    agent_id=agent_id,
                    generation=generation,
                    amp_kind=amp_kind,
                )
                return record
            except IDAError:
                self._burn(seq, "amplify")
                raise

    # -- distill --------------------------------------------------------------

    def distill(
        self,
        amplification_id: str,
        successor_id: str,
        seq: int,
        strategy: str = "imitation-learning",
        verdict: str = "not-evaluated",
        plan_digest: str = "",
    ) -> DistillationRecord:
        """Book one declared distillation into a successor agent.

        Fail-closed: the amplification must be booked, may only be distilled
        once, and the successor must be a fresh id distinct from the parent.
        The verdict is data, never proof the distillation preserved
        alignment.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(amplification_id, "amplification_id")
                _require_id(successor_id, "successor_id")
                if amplification_id not in self._amplifications:
                    raise UnknownAmplificationError(
                        f"unknown amplification: {amplification_id!r}"
                    )
                if amplification_id in self._amplification_distillation:
                    raise AlreadyDistilledError(
                        f"amplification already distilled: {amplification_id!r}"
                    )
                if strategy not in DISTILL_STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                if verdict not in DISTILL_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                plan_digest = _require_optional_digest(plan_digest, "plan_digest")
                parent = self._amplifications[amplification_id]
                if successor_id == parent.agent_id:
                    raise SelfDistillError(
                        f"successor equals parent: {successor_id!r}"
                    )
                if successor_id in self._generations:
                    raise DuplicateSuccessorError(
                        f"successor already registered: {successor_id!r}"
                    )
                generation = parent.generation + 1
                self._dst_counter += 1
                distillation_id = f"dst-{self._dst_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "distillation_id": distillation_id,
                        "amplification_id": amplification_id,
                        "parent_id": parent.agent_id,
                        "successor_id": successor_id,
                        "generation": generation,
                        "strategy": strategy,
                        "verdict": verdict,
                        "plan_digest": plan_digest,
                        "seq": seq,
                    }
                )
                record = DistillationRecord(
                    distillation_id=distillation_id,
                    amplification_id=amplification_id,
                    parent_id=parent.agent_id,
                    successor_id=successor_id,
                    generation=generation,
                    strategy=strategy,
                    verdict=verdict,
                    plan_digest=plan_digest,
                    seq=seq,
                    digest=digest,
                )
                self._distillations[distillation_id] = record
                self._amplification_distillation[amplification_id] = (
                    distillation_id
                )
                self._generations[successor_id] = generation
                self._emit(
                    "distilled",
                    seq,
                    distillation_id=distillation_id,
                    amplification_id=amplification_id,
                    parent_id=parent.agent_id,
                    successor_id=successor_id,
                    generation=generation,
                    strategy=strategy,
                    verdict=verdict,
                )
                return record
            except IDAError:
                self._burn(seq, "distill")
                raise

    # -- iterate (pure read) ----------------------------------------------------

    def iterate(self, seq: int, agent_id: str = "") -> IterationReport:
        """Derived IDA trajectory posture, as data.

        Scoped to one agent's trajectory (all generations from that root)
        when ``agent_id`` is given, else the whole ledger.

        Posture rules (ledger data, never measured truth):
        - ``unstarted`` when no amplifications are booked in scope
        - ``diverged`` when any booked distillation verdict is ``misaligned``
        - ``uncertain`` when any verdict is ``uncertain`` (and none misaligned)
        - ``aligned-chain`` when >= 1 distillation is booked and every
          verdict is ``aligned``
        - ``unevaluated`` otherwise (distillations booked, none evaluated)
        """
        with self._lock:
            self._check_seq(seq)
            scoped = agent_id != ""
            if scoped:
                _require_id(agent_id, "agent_id")
                if agent_id not in self._generations:
                    raise UnknownAgentError(f"unknown agent: {agent_id!r}")
                agents = {agent_id}
            else:
                agents = set(self._generations)
            amps = [
                rec
                for rec in self._amplifications.values()
                if rec.agent_id in agents
            ]
            dsts = [
                rec
                for rec in self._distillations.values()
                if rec.parent_id in agents
            ]
            all_ok = all(rec.verify() for rec in amps) and all(
                rec.verify() for rec in dsts
            )
            max_generation = max(
                [self._generations[a] for a in agents] + [-1]
            )
            verdicts = {rec.verdict for rec in dsts}
            if not amps:
                posture = "unstarted"
            elif "misaligned" in verdicts:
                posture = "diverged"
            elif "uncertain" in verdicts:
                posture = "uncertain"
            elif dsts and verdicts == {"aligned"}:
                posture = "aligned-chain"
            else:
                posture = "unevaluated"
            record = IterationReport(
                agent_id=agent_id,
                scoped=scoped,
                n_agents=len(agents),
                n_amplifications=len(amps),
                n_distillations=len(dsts),
                max_generation=max_generation,
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "agent_id": agent_id,
                        "scoped": scoped,
                        "n_agents": len(agents),
                        "n_amplifications": len(amps),
                        "n_distillations": len(dsts),
                        "max_generation": max_generation,
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) -----------------------------------------------------

    def amplification_record(
        self, amplification_id: str, seq: int
    ) -> AmplificationRecord:
        """Return one amplification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(amplification_id, "amplification_id")
            if amplification_id not in self._amplifications:
                raise UnknownAmplificationError(
                    f"unknown amplification: {amplification_id!r}"
                )
            return self._amplifications[amplification_id]

    def distillation_record(
        self, distillation_id: str, seq: int
    ) -> DistillationRecord:
        """Return one distillation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(distillation_id, "distillation_id")
            if distillation_id not in self._distillations:
                raise UnknownAmplificationError(
                    f"unknown distillation: {distillation_id!r}"
                )
            return self._distillations[distillation_id]

    def amplifications_for(self, agent_id: str, seq: int) -> Tuple[str, ...]:
        """Amplification ids booked for one agent, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._generations:
                raise UnknownAgentError(f"unknown agent: {agent_id!r}")
            return tuple(self._agent_amplifications.get(agent_id, ()))

    def distillation_for(self, amplification_id: str, seq: int) -> str:
        """Distillation id booked for one amplification (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(amplification_id, "amplification_id")
            if amplification_id not in self._amplifications:
                raise UnknownAmplificationError(
                    f"unknown amplification: {amplification_id!r}"
                )
            if amplification_id not in self._amplification_distillation:
                raise UnknownAmplificationError(
                    f"amplification has no distillation: {amplification_id!r}"
                )
            return self._amplification_distillation[amplification_id]

    def agent_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered agent ids in registration order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._generations.keys())

    def amplification_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked amplification ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._amplifications.keys())

    def distillation_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked distillation ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._distillations.keys())

    def successor_ids(self, agent_id: str, seq: int) -> Tuple[str, ...]:
        """Successor ids distilled from one parent agent (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._generations:
                raise UnknownAgentError(f"unknown agent: {agent_id!r}")
            return tuple(
                rec.successor_id
                for rec in self._distillations.values()
                if rec.parent_id == agent_id
            )

    def generation_of(self, agent_id: str, seq: int) -> int:
        """Registered generation of one agent (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(agent_id, "agent_id")
            if agent_id not in self._generations:
                raise UnknownAgentError(f"unknown agent: {agent_id!r}")
            return self._generations[agent_id]

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "agents": len(self._generations),
                "amplifications": len(self._amplifications),
                "distillations": len(self._distillations),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the IDA ledger end to end."""
    ida = IDA()
    a1 = ida.amplify("m-0", 1, amp_kind="hch-decomposition")
    d1 = ida.distill(a1.amplification_id, "m-1", 2, verdict="aligned")
    assert d1.generation == 1
    assert ida.generation_of("m-1", 3) == 1
    assert ida.iterate(4, "m-0").posture == "aligned-chain"
    a2 = ida.amplify("m-1", 5, amp_kind="parallel-ensemble")
    ida.distill(a2.amplification_id, "m-2", 6, verdict="not-evaluated")
    assert ida.iterate(7, "m-1").posture == "unevaluated"
    assert ida.stats(8) == {
        "agents": 3,
        "amplifications": 2,
        "distillations": 2,
        "rejected": 0,
    }
    print("ida OK: amplify, distill, iterate, pins, audit")


if __name__ == "__main__":
    main()
