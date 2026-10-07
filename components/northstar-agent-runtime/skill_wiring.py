"""Skill and code-mode per-call wiring: authorization + budget in the path.

A skill file is text the model reads (:mod:`skills`, :mod:`skill_audit`); this
module is the *execution* side. Reading a skill never grants anything: every
individual invocation of a skill - and every code-mode execution - must pass
an authorization check and a budget charge *before* anything runs. The
enforcement lives in the call path, not in the model's good intentions.

Honest scope: this module wires the gate; it does not sandbox code. The
``executor`` callable injected into :class:`CodeModeSession` is supplied by
the host (its sandbox, seccomp, bwrap binding surface), and this module never
verifies that the executor is actually safe - it only guarantees that an
unauthorized or over-budget call never reaches it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

#: Version pin for records minted by this module.
SKILL_WIRING_VERSION = "skill-wiring.v1"


class SkillWiringError(ValueError):
    """Base error for skill-wiring misuse (bad policy, unknown skill, ...)."""


class UnauthorizedCall(SkillWiringError):
    """The call was denied by the authorization policy."""


class BudgetExhausted(SkillWiringError):
    """The call was denied because the budget is exhausted."""


class ClosedSession(SkillWiringError):
    """An operation was attempted on a closed code-mode session."""


@dataclass(frozen=True)
class SkillCall:
    """One invocation of a skill, before authorization."""

    skill_name: str
    args_hash: str  # hex digest of the canonicalized arguments
    caller_id: str
    seq: int  # caller-supplied sequence number; no wall clock is read

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "args_hash": self.args_hash,
            "caller_id": self.caller_id,
            "seq": self.seq,
            "version": SKILL_WIRING_VERSION,
        }


def args_digest(args: Any) -> str:
    """Deterministic hex digest of canonicalized call arguments."""
    import json

    try:
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        canonical = repr(args)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SkillPolicy:
    """Per-skill authorization policy."""

    skill_name: str
    allowed_callers: frozenset[str]  # empty = nobody
    estimated_cost_usd: float = 0.0
    requires_review: bool = False  # human review before first use


@dataclass
class SkillRegistry:
    """Maps skill names to their authorization policies."""

    _policies: dict[str, SkillPolicy] = field(default_factory=dict)

    def register(self, policy: SkillPolicy) -> None:
        if not policy.skill_name:
            raise SkillWiringError("skill name must be non-empty")
        if policy.estimated_cost_usd < 0:
            raise SkillWiringError("estimated cost must be non-negative")
        self._policies[policy.skill_name] = policy

    def policy_for(self, skill_name: str) -> SkillPolicy | None:
        return self._policies.get(skill_name)

    def known_skills(self) -> tuple[str, ...]:
        return tuple(sorted(self._policies))


def authorize_skill_call(call: SkillCall, policy: SkillPolicy | None) -> bool:
    """Return True only if the call is authorized.

    Fail-closed: unknown skills (``policy is None``), callers not in the
    allow-list, empty caller ids, and name mismatches all deny.
    """
    if policy is None:
        return False
    if call.skill_name != policy.skill_name:
        return False
    if not call.caller_id:
        return False
    return call.caller_id in policy.allowed_callers


@dataclass
class CallBudget:
    """Per-session spend envelope for skill and code-mode calls.

    Costs are estimates in USD; the budget is a ceiling, not a ledger of
    actual provider charges. Fail-closed: when the ceiling would be exceeded,
    the call is denied before it runs.
    """

    ceiling_usd: float
    spent_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.ceiling_usd < 0:
            raise SkillWiringError("budget ceiling must be non-negative")
        if self.spent_usd < 0:
            raise SkillWiringError("spent must be non-negative")
        if self.spent_usd > self.ceiling_usd:
            raise SkillWiringError("spent exceeds ceiling at construction")

    def try_charge(self, amount_usd: float) -> bool:
        """Charge the budget; return False (deny) if the ceiling would break."""
        if amount_usd < 0:
            return False
        if self.spent_usd + amount_usd > self.ceiling_usd + 1e-12:
            return False
        self.spent_usd = round(self.spent_usd + amount_usd, 10)
        return True

    @property
    def remaining(self) -> float:
        return round(max(0.0, self.ceiling_usd - self.spent_usd), 10)

    @property
    def exhausted(self) -> bool:
        return self.spent_usd >= self.ceiling_usd


@dataclass(frozen=True)
class SkillDecision:
    """Authorized + budgeted decision for one skill call."""

    call: SkillCall
    allowed: bool
    reason: str  # "authorized" | "unauthorized" | "budget-exhausted"
    cost_usd: float


def decide_skill_call(
    call: SkillCall,
    registry: SkillRegistry,
    budget: CallBudget,
) -> SkillDecision:
    """Authorize then charge; the budget is only touched when authorized.

    Returns a :class:`SkillDecision`; callers that need exceptions can raise
    from it. Ordering is fixed: authorization first, budget second.
    """
    policy = registry.policy_for(call.skill_name)
    if not authorize_skill_call(call, policy):
        return SkillDecision(call=call, allowed=False, reason="unauthorized", cost_usd=0.0)
    cost = policy.estimated_cost_usd if policy is not None else 0.0
    if not budget.try_charge(cost):
        return SkillDecision(call=call, allowed=False, reason="budget-exhausted", cost_usd=cost)
    return SkillDecision(call=call, allowed=True, reason="authorized", cost_usd=cost)


#: Estimated cost for one code-mode execution, billed per call.
CODE_MODE_COST_USD = 0.02


class CodeModeSession:
    """A code-execution session where every execute() is gated.

    The session holds a reference to the :class:`SkillRegistry` (code-mode
    is registered as a pseudo-skill named ``"code-mode"``), a per-session
    budget, and the host-supplied ``executor`` callable. ``execute()``:

    1. builds a :class:`SkillCall` for the code digest,
    2. authorizes it against the registry,
    3. charges the budget,
    4. only then invokes the executor.

    The executor receives the raw code string and returns whatever the host
    sandbox returns. This module never inspects or runs the code itself.
    """

    CODE_MODE_SKILL = "code-mode"

    def __init__(
        self,
        *,
        caller_id: str,
        registry: SkillRegistry,
        budget: CallBudget,
        executor: Callable[[str], Any],
        cost_usd: float = CODE_MODE_COST_USD,
    ) -> None:
        if not caller_id:
            raise SkillWiringError("caller_id must be non-empty")
        if cost_usd < 0:
            raise SkillWiringError("cost must be non-negative")
        self._caller_id = caller_id
        self._registry = registry
        self._budget = budget
        self._executor = executor
        self._cost_usd = cost_usd
        self._seq = 0
        self._closed = False
        self._executed = 0

    @property
    def caller_id(self) -> str:
        return self._caller_id

    @property
    def executed_count(self) -> int:
        return self._executed

    @property
    def closed(self) -> bool:
        return self._closed

    def execute(self, code: str) -> Any:
        """Run code through authorization + budget, then the host executor."""
        if self._closed:
            raise ClosedSession("session is closed")
        if not isinstance(code, str) or not code:
            raise SkillWiringError("code must be a non-empty string")
        self._seq += 1
        call = SkillCall(
            skill_name=self.CODE_MODE_SKILL,
            args_hash=args_digest(code),
            caller_id=self._caller_id,
            seq=self._seq,
        )
        policy = self._registry.policy_for(self.CODE_MODE_SKILL)
        if not authorize_skill_call(call, policy):
            raise UnauthorizedCall(
                f"caller {self._caller_id!r} is not authorized for code-mode"
            )
        if not self._budget.try_charge(self._cost_usd):
            raise BudgetExhausted(
                f"code-mode budget exhausted (cost {self._cost_usd}, "
                f"remaining {self._budget.remaining})"
            )
        result = self._executor(code)
        self._executed += 1
        return result

    def close(self) -> None:
        self._closed = True


def make_default_registry(
    skills: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    code_mode_callers: tuple[str, ...] = (),
    code_mode_cost_usd: float = CODE_MODE_COST_USD,
) -> SkillRegistry:
    """Build a registry from a plain spec dict.

    ``skills`` maps skill name to ``{"allowed_callers": [...], "estimated_cost_usd": x}``.
    """
    registry = SkillRegistry()
    for name, spec in (skills or {}).items():
        registry.register(
            SkillPolicy(
                skill_name=name,
                allowed_callers=frozenset(spec.get("allowed_callers", ())),
                estimated_cost_usd=float(spec.get("estimated_cost_usd", 0.0)),
            )
        )
    registry.register(
        SkillPolicy(
            skill_name=CodeModeSession.CODE_MODE_SKILL,
            allowed_callers=frozenset(code_mode_callers),
            estimated_cost_usd=code_mode_cost_usd,
        )
    )
    return registry
