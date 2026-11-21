"""Finding gate: seven questions asked in order before a finding ships.

What was missing
----------------
Northstar's acceptance ledger (2026-11-15: 68 slices re-run, 32 pass / 36
fail) and the mutant probes keep producing **false kills**: a finding that
is not real wastes the whole pipeline, because the judge and the
mutant-evidence machinery trust findings.  A false finding poisons
acceptance, and a poisoned acceptance ledger cannot be distinguished from a
strict one by reading it.

The runtime already had the machinery to *hold* something -- the refusal
hold (``refusal_hold.py``, ``refusal_hold_wiring.py``) holds a refusal and
lets the run continue -- but no machinery to decide **whether a finding
deserves to be shipped at all**.  A finding was either reported or it was
not; there was no gate between "the tester saw something" and "the finding
goes into the ledger".

The source
----------
Claude-BugHunter by Sachin Sharma, ``triage-validation`` skill:
https://github.com/elementalsouls/Claude-BugHunter.git
(code MIT / content CC BY 4.0).

The source's contribution is a **gate**, not a scanner: a small number of
questions asked *in a fixed order*, where the first answer that comes back
"no" is the end of the discussion for that finding.  Two of its rules shape
this module the most:

* a **pre-gate** of three questions -- what can the attacker actually do
  right now, what does the victim actually lose, and can it be reproduced
  from scratch in ten minutes -- is asked *before* the main list, so that a
  finding which fails any of them never reaches the interesting questions;
* a **layer-ordering trap**: an error response does not prove that
  authentication was passed.  A sanitiser or a body parser can reject a
  request *before* the authentication middleware ever sees it, so a
  "bypass" demonstrated only by a status code is usually a parser
  rejecting the request, not an authorization hole.  The check that
  distinguishes the two is a re-send with a minimal well-formed body.

Northstar re-derives both in its own vocabulary (see the seven questions
below).  **No code, no skill text and no payload table from the source is
copied here**: the questions are Northstar's own wording, the finding
vocabulary is Northstar's own, and the gate is a pure function of the
finding.

Northstar extensions (explicitly **not** from the source)
----------------------------------------------------------
* **The verdict vocabulary.**  ``PASS`` / ``KILL`` / ``CHAIN-REQUIRED`` /
  ``DOWNGRADE`` is Northstar's.  The source kills or reports a finding; it
  does not route one to a chain builder or lower its severity.
* **The accepted-impact list and the in-scope asset** are Northstar's
  program-side vocabulary, and they are *inputs* to the gate rather than
  hard-coded policy: the caller names the impact kind and the asset, and
  the gate checks the naming against the module's own lists.
* **The Layer-Ordering Trap is enforced structurally**, as three separate
  refusals (a status-code-only proof, an error-response-only proof, and an
  authentication-bypass claim with no minimal-body re-send on record), not
  as one advisory sentence.
* **The wiring point** is Northstar's refusal-hold seam: a killed finding
  is recorded as a refusal row through the existing registry, so "held" is
  an auditable row and not a silent drop.

Scope: this module is a pure library.  It performs no network access, no
I/O, no clock read and no randomness, so the same finding yields the same
verdict on every run -- which is what lets the mutant probe and the bench
exercise it deterministically.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any, Dict, Mapping, Optional, Tuple

__all__ = [
    "Finding",
    "Verdict",
    "evaluate_finding",
    "apply_finding_gate",
    "GateDecision",
    "finding_digest",
    "QUESTIONS",
    "GATE_0_QUESTIONS",
    "VERDICT_PASS",
    "VERDICT_KILL",
    "VERDICT_CHAIN_REQUIRED",
    "VERDICT_DOWNGRADE",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
    "ACCEPTED_IMPACT_KINDS",
    "PROOF_NONE",
    "PROOF_STATUS_CODE",
    "PROOF_ERROR_RESPONSE",
    "PROOF_CONCRETE",
    "FindingGateError",
]


#: The four verdicts.  These are plain strings so a verdict can be written
#: into a ledger row, a report and a log line without a conversion step.
VERDICT_PASS = "PASS"
VERDICT_KILL = "KILL"
VERDICT_CHAIN_REQUIRED = "CHAIN-REQUIRED"
VERDICT_DOWNGRADE = "DOWNGRADE"

#: The severity ladder, highest first.  A downgraded finding moves one
#: step down the ladder.
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

_SEVERITY_ORDER: Tuple[str, ...] = (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW)

#: The impact kinds the program accepts.  A finding whose impact is not on
#: this list is out of scope for reporting, whatever else it may have.
ACCEPTED_IMPACT_KINDS: Tuple[str, ...] = (
    "authentication-bypass",
    "authorization-bypass",
    "code-execution",
    "data-exposure",
    "integrity",
    "availability",
    "sensitive-disclosure",
)

#: The kinds of proof a finding can carry.  ``PROOF_STATUS_CODE`` and
#: ``PROOF_ERROR_RESPONSE`` are the **layer-ordering trap**: neither one
#: proves that authentication was passed.
PROOF_NONE = "none"
PROOF_STATUS_CODE = "status-code"
PROOF_ERROR_RESPONSE = "error-response"
PROOF_CONCRETE = "concrete"

_PROOF_KINDS: Tuple[str, ...] = (
    PROOF_NONE,
    PROOF_STATUS_CODE,
    PROOF_ERROR_RESPONSE,
    PROOF_CONCRETE,
)

#: Privilege descriptors that mean "no privilege the attacker cannot get".
_UNPRIVILEGED = ("", "none", "unprivileged", "no-privilege", "no-privilege-required")

#: The HTTP methods a real request can be written with.
_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


class FindingGateError(ValueError):
    """A finding is malformed and cannot be gated."""


@dataclass(frozen=True)
class Verdict:
    """The gate's answer about one finding.

    ``outcome`` is one of the four verdict constants.  ``question`` names
    the gate step that produced the answer (``"gate-0"`` for the pre-gate,
    ``"q1"`` .. ``"q7"`` for the seven questions, ``"final"`` for the
    severity step), and ``reason`` is a one-line, human-readable
    explanation that can go straight into a report.

    The verdict carries the **resulting severity**: for
    :data:`VERDICT_DOWNGRADE` that is the lowered severity, and for every
    other outcome it is the severity the finding was filed with.
    """

    outcome: str
    question: str
    reason: str
    severity: str = SEVERITY_HIGH

    @property
    def killed(self) -> bool:
        """True when the finding is held rather than shipped."""
        return self.outcome == VERDICT_KILL

    @property
    def shipped(self) -> bool:
        """True when the finding may be shipped (PASS or DOWNGRADE)."""
        return self.outcome in (VERDICT_PASS, VERDICT_DOWNGRADE)

    def as_dict(self) -> Dict[str, str]:
        """The verdict as a plain dict."""
        return {
            "outcome": self.outcome,
            "question": self.question,
            "reason": self.reason,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class Finding:
    """One finding, carrying exactly what the gate's questions need.

    The fields map onto the seven questions and onto the pre-gate:

    ==========================  ==========================================
    field                       question it answers
    ==========================  ==========================================
    ``attacker_steps``          q1 -- the steps, written as real requests
    ``impact_kind``             q2 -- is the impact on the accepted list
    ``in_scope_asset``          q3 -- the in-scope asset the root cause
                                    lives in
    ``required_privilege``      q4 -- the privilege the attack needs
    ``known_behavior``          q5 -- is this already known behaviour
    ``impact_proof``            q6 -- the proof, beyond "possible"
    ``impact_proof_kind``       q6 -- what *kind* of proof it is
    ``minimal_body_resent``     q6 -- the layer-ordering re-send
    ``never_submit``            q7 -- the never-submit list
    ``attacker_can_act_now``    pre-gate -- can the attacker act right now
    ``impact``                  pre-gate -- what the victim loses
    ``repro_minutes``           pre-gate -- reproducible in ten minutes
    ``severity``                severity step
    ``chain_required``          q6 -- impact needs a second step
    ==========================  ==========================================

    ``attacker_steps`` holds the steps as **real HTTP requests**: a
    method, a target and (optionally) a body.  A step that cannot be
    written as a request is a step that cannot be carried out, and the
    gate refuses to accept it as one.
    """

    attacker_steps: Tuple[str, ...] = ()
    impact: str = ""
    impact_kind: str = ""
    in_scope_asset: str = ""
    required_privilege: str = ""
    known_behavior: bool = False
    impact_proof: str = ""
    impact_proof_kind: str = PROOF_NONE
    minimal_body_resent: bool = False
    never_submit: bool = False
    attacker_can_act_now: bool = True
    repro_minutes: Optional[int] = 10
    severity: str = SEVERITY_HIGH
    chain_required: bool = False
    claims_auth_bypass: bool = False
    low_impact: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "attacker_steps", _steps_tuple(self.attacker_steps))
        object.__setattr__(self, "impact", _text(self.impact, "impact"))
        object.__setattr__(self, "impact_kind", _text(self.impact_kind, "impact_kind"))
        object.__setattr__(self, "in_scope_asset", _text(self.in_scope_asset, "in_scope_asset"))
        object.__setattr__(self, "required_privilege", _text(self.required_privilege, "required_privilege"))
        object.__setattr__(self, "impact_proof", _text(self.impact_proof, "impact_proof"))
        object.__setattr__(self, "known_behavior", bool(self.known_behavior))
        object.__setattr__(self, "minimal_body_resent", bool(self.minimal_body_resent))
        object.__setattr__(self, "never_submit", bool(self.never_submit))
        object.__setattr__(self, "attacker_can_act_now", bool(self.attacker_can_act_now))
        object.__setattr__(self, "chain_required", bool(self.chain_required))
        object.__setattr__(self, "claims_auth_bypass", bool(self.claims_auth_bypass))
        object.__setattr__(self, "low_impact", bool(self.low_impact))
        severity = _text(self.severity, "severity") or SEVERITY_HIGH
        if severity not in _SEVERITY_ORDER:
            raise FindingGateError(
                "severity must be one of %s, got %r" % (", ".join(_SEVERITY_ORDER), severity)
            )
        object.__setattr__(self, "severity", severity)
        proof_kind = _text(self.impact_proof_kind, "impact_proof_kind") or PROOF_NONE
        if proof_kind not in _PROOF_KINDS:
            raise FindingGateError(
                "impact_proof_kind must be one of %s, got %r"
                % (", ".join(_PROOF_KINDS), proof_kind)
            )
        object.__setattr__(self, "impact_proof_kind", proof_kind)
        minutes = self.repro_minutes
        if minutes is not None:
            if isinstance(minutes, bool) or not isinstance(minutes, int):
                raise FindingGateError(
                    "repro_minutes must be an int or None, got %r" % (minutes,)
                )
            if minutes < 0:
                raise FindingGateError(
                    "repro_minutes must not be negative, got %r" % (minutes,)
                )
        object.__setattr__(self, "repro_minutes", minutes)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Finding":
        """Build a finding from a plain mapping.

        Unknown keys are refused rather than ignored: a field the gate does
        not know about is a field the gate does not check, and a silently
        dropped field is how a finding gets shipped without a question
        having been asked.
        """
        if not isinstance(value, Mapping):
            raise FindingGateError("a finding mapping is required, got %r" % (type(value).__name__,))
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        unknown = sorted(set(value) - known)
        if unknown:
            raise FindingGateError(
                "unknown finding field(s): %s" % ", ".join(unknown)
            )
        return cls(**dict(value))

    def with_severity(self, severity: str) -> "Finding":
        """A copy of this finding at another severity."""
        return replace(self, severity=severity)

    def as_dict(self) -> Dict[str, Any]:
        """The finding as a plain dict (the fields it was built from)."""
        return {
            "attacker_steps": list(self.attacker_steps),
            "impact": self.impact,
            "impact_kind": self.impact_kind,
            "in_scope_asset": self.in_scope_asset,
            "required_privilege": self.required_privilege,
            "known_behavior": self.known_behavior,
            "impact_proof": self.impact_proof,
            "impact_proof_kind": self.impact_proof_kind,
            "minimal_body_resent": self.minimal_body_resent,
            "never_submit": self.never_submit,
            "attacker_can_act_now": self.attacker_can_act_now,
            "repro_minutes": self.repro_minutes,
            "severity": self.severity,
            "chain_required": self.chain_required,
            "claims_auth_bypass": self.claims_auth_bypass,
            "low_impact": self.low_impact,
        }


def _text(value: Any, name: str) -> str:
    """A text field: a string, or refused."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FindingGateError("%s must be a string, got %r" % (name, type(value).__name__))
    return value.strip()


def _steps_tuple(value: Any) -> Tuple[str, ...]:
    """The attacker steps, as a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        raise FindingGateError(
            "attacker_steps must be a sequence of steps, not one string"
        )
    if not isinstance(value, (list, tuple)):
        raise FindingGateError(
            "attacker_steps must be a sequence, got %r" % (type(value).__name__,)
        )
    steps = []
    for index, step in enumerate(value):
        if not isinstance(step, str):
            raise FindingGateError(
                "attacker_steps[%d] must be a string, got %r" % (index, type(step).__name__)
            )
        steps.append(step.strip())
    return tuple(steps)


def _is_real_request(step: str) -> bool:
    """True when a step can be written as a real HTTP request.

    A step that names a method and a target is a request.  A step that is
    prose ("the attacker logs in as the admin") is not: the gate's first
    question asks whether the attack can be carried out *step by step*, and
    a prose step cannot be carried out by anything.
    """
    if not step:
        return False
    head = step.split(None, 1)
    if not head:
        return False
    method = head[0].upper()
    if method not in _HTTP_METHODS:
        return False
    rest = head[1] if len(head) > 1 else ""
    if not rest:
        return False
    target = rest.split()[0]
    if not target.startswith("/") and "://" not in target:
        return False
    return True


def _lower_severity(severity: str) -> str:
    """The next severity down the ladder (the floor is ``low``)."""
    index = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[min(index + 1, len(_SEVERITY_ORDER) - 1)]


#: The seven questions, in the order they are asked.  The names are
#: Northstar's own; the order and the "first NO ends it" rule are the
#: source's shape.
QUESTIONS: Tuple[str, ...] = (
    "q1-can-the-attacker-act-now",
    "q2-is-the-impact-accepted",
    "q3-is-the-root-cause-in-scope",
    "q4-is-the-privilege-available",
    "q5-is-it-new-behaviour",
    "q6-is-the-impact-proved",
    "q7-is-it-submittable",
)

#: The three pre-gate questions, asked before any of the seven.
GATE_0_QUESTIONS: Tuple[str, ...] = (
    "gate-0-can-the-attacker-act-now",
    "gate-0-what-does-the-victim-lose",
    "gate-0-is-it-reproducible-in-ten-minutes",
)


def _gate_0(finding: Finding) -> Optional[Verdict]:
    """The pre-gate: three questions, asked first, each fatal.

    A finding that fails any one of them is killed before the seven
    questions run.  The order inside the pre-gate is fixed, so the reason
    a finding was killed is always the *first* thing wrong with it.
    """
    if not finding.attacker_can_act_now:
        return Verdict(
            VERDICT_KILL,
            GATE_0_QUESTIONS[0],
            "the attacker cannot act on this right now; the finding describes a "
            "future or theoretical capability",
            finding.severity,
        )
    if not finding.impact.strip():
        return Verdict(
            VERDICT_KILL,
            GATE_0_QUESTIONS[1],
            "the victim loses nothing: the finding names no impact",
            finding.severity,
        )
    minutes = finding.repro_minutes
    if minutes is None or minutes > 10:
        return Verdict(
            VERDICT_KILL,
            GATE_0_QUESTIONS[2],
            "the finding is not reproducible from scratch in ten minutes "
            "(stated: %s)" % ("unknown" if minutes is None else str(minutes)),
            finding.severity,
        )
    return None


def _q1(finding: Finding) -> Optional[Verdict]:
    """Can an attacker use this RIGHT NOW, step by step?"""
    steps = finding.attacker_steps
    if not steps:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[0],
            "the finding states no attacker steps, so it cannot be used right now",
            finding.severity,
        )
    if not all(_is_real_request(step) for step in steps):
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[0],
            "the attacker steps are not written as real requests; a step that "
            "cannot be sent is a step that cannot be carried out",
            finding.severity,
        )
    return None


def _q2(finding: Finding) -> Optional[Verdict]:
    """Is the impact on the program's accepted impact list?"""
    if not finding.impact_kind.strip():
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[1],
            "the finding names no impact kind, so it cannot be checked against "
            "the accepted impact list",
            finding.severity,
        )
    if finding.impact_kind not in ACCEPTED_IMPACT_KINDS:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[1],
            "the impact kind %r is not on the accepted impact list"
            % (finding.impact_kind,),
            finding.severity,
        )
    return None


def _q3(finding: Finding) -> Optional[Verdict]:
    """Is the root cause in an in-scope asset?"""
    if not finding.in_scope_asset.strip():
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[2],
            "the finding names no in-scope asset, so its root cause cannot be "
            "placed",
            finding.severity,
        )
    return None


def _q4(finding: Finding) -> Optional[Verdict]:
    """Does it work without privileged access an attacker cannot get?"""
    privilege = finding.required_privilege.strip().lower()
    if privilege in _UNPRIVILEGED:
        return None
    return Verdict(
        VERDICT_KILL,
        QUESTIONS[3],
        "the finding requires the privilege %r, which an attacker cannot get"
        % (finding.required_privilege,),
        finding.severity,
    )


def _q5(finding: Finding) -> Optional[Verdict]:
    """Is this not already known or documented behaviour?"""
    if finding.known_behavior:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[4],
            "the behaviour is already known or documented; reporting it again "
            "adds no finding",
            finding.severity,
        )
    return None


def _q6(finding: Finding) -> Optional[Verdict]:
    """Can impact be proved beyond "technically possible"?

    This is where the **layer-ordering trap** lives.  An error response or
    a status code proves that *something* rejected the request; it does
    not prove that authentication was passed and then bypassed.  A
    sanitiser or a body parser can reject the request before the
    authentication middleware runs, so the re-send with a minimal
    well-formed body is the check that tells the two apart.
    """
    kind = finding.impact_proof_kind
    if kind == PROOF_NONE or not finding.impact_proof.strip():
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[5],
            "the impact is not proved: a finding that is only technically "
            "possible is not a finding",
            finding.severity,
        )
    if kind == PROOF_STATUS_CODE:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[5],
            "the only evidence is a status code; a status code does not prove "
            "that authentication was passed (the layer-ordering trap): "
            "re-send with a minimal well-formed body",
            finding.severity,
        )
    if kind == PROOF_ERROR_RESPONSE:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[5],
            "the only evidence is an error response; a body parser or a "
            "sanitiser can reject a request before authentication runs (the "
            "layer-ordering trap): re-send with a minimal well-formed body",
            finding.severity,
        )
    if finding.claims_auth_bypass and not finding.minimal_body_resent:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[5],
            "the claim is an authentication bypass, but no minimal "
            "well-formed-body re-send is on record (the layer-ordering trap)",
            finding.severity,
        )
    if finding.chain_required:
        return Verdict(
            VERDICT_CHAIN_REQUIRED,
            QUESTIONS[5],
            "the impact is proved only after a second step; the finding is "
            "routed to the chain builder",
            finding.severity,
        )
    return None


def _q7(finding: Finding) -> Optional[Verdict]:
    """Is this not on the never-submit list?"""
    if finding.never_submit:
        return Verdict(
            VERDICT_KILL,
            QUESTIONS[6],
            "the finding is on the never-submit list",
            finding.severity,
        )
    return None


def evaluate_finding(finding: Any) -> Verdict:
    """Run the gate over one finding and return its verdict.

    The order is fixed and the gate is **total**: every finding gets an
    answer, and the first question whose answer is "no" ends the
    assessment.  The pre-gate (three questions) runs before the seven.

    The function is pure: it reads nothing but its argument, and it
    returns the same verdict for the same finding on every run.
    """
    if not isinstance(finding, Finding):
        if isinstance(finding, Mapping):
            finding = Finding.from_mapping(finding)
        else:
            raise FindingGateError(
                "a Finding is required, got %r" % (type(finding).__name__,)
            )
    early = _gate_0(finding)
    if early is not None:
        return early
    for step in (_q1, _q2, _q3, _q4, _q5, _q6, _q7):
        verdict = step(finding)
        if verdict is not None:
            return verdict
    if finding.low_impact or finding.severity == SEVERITY_LOW:
        lowered = _lower_severity(finding.severity)
        return Verdict(
            VERDICT_DOWNGRADE,
            "final",
            "the finding is real but its impact is low; it ships at %s severity"
            % (lowered,),
            lowered,
        )
    return Verdict(
        VERDICT_PASS,
        "final",
        "the finding passed the pre-gate and all seven questions",
        finding.severity,
    )


# ---------------------------------------------------------------------------
# The seam: a finding that would be accepted goes through the gate first.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateDecision:
    """What the gate did with one finding at the seam.

    ``action`` is one of:

    ``"ship"``
        the finding may be shipped as it stands (``PASS``);
    ``"hold"``
        the finding is held and **not** shipped (``KILL``); the run
        continues;
    ``"chain"``
        the finding is routed to the chain builder (``CHAIN-REQUIRED``);
    ``"downgrade"``
        the finding ships at a lowered severity (``DOWNGRADE``).

    ``held`` is true for ``"hold"``, and it is the flag the caller reads to
    decide whether to keep going: a killed finding stops the *finding*, not
    the run.
    """

    action: str
    verdict: Verdict
    finding: Finding

    @property
    def held(self) -> bool:
        """True when the finding is held rather than shipped."""
        return self.action == "hold"

    @property
    def shipped(self) -> bool:
        """True when the finding may be shipped."""
        return self.action in ("ship", "downgrade")

    @property
    def needs_chain(self) -> bool:
        """True when the finding is routed to the chain builder."""
        return self.action == "chain"

    def as_dict(self) -> Dict[str, Any]:
        """The decision as a plain dict."""
        return {
            "action": self.action,
            "verdict": self.verdict.as_dict(),
            "finding": self.finding.as_dict(),
        }


_ACTION_BY_OUTCOME = {
    VERDICT_PASS: "ship",
    VERDICT_KILL: "hold",
    VERDICT_CHAIN_REQUIRED: "chain",
    VERDICT_DOWNGRADE: "downgrade",
}


def finding_digest(finding: Finding) -> str:
    """A stable digest of one finding.

    The digest is over the finding's own fields, in a fixed order, with no
    clock and no randomness -- so the same finding always has the same
    digest, and two different findings do not share one.  It is what the
    seam records as the evidence hash of the held finding.
    """
    payload = json.dumps(finding.as_dict(), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def apply_finding_gate(
    finding: Any,
    *,
    registry: Any = None,
    grant_id: str = "",
    action: str = "ship_finding",
    subject: str = "",
    now: Optional[float] = None,
) -> GateDecision:
    """Run the gate at the refusal-hold seam.

    This is the **read-only check**: the gate is consulted before a
    finding is accepted, and it is a pure function of the finding, so it
    never mutates the finding and never decides anything about the run.

    When a ``registry`` is supplied (the refusal-hold wiring's
    :class:`~refusal_hold_wiring.RefusalHoldRegistry`), a **killed**
    finding is *held*: it is recorded as a refusal row through the
    registry's existing ``record()`` seam, so the hold is an auditable row
    rather than a silent drop.  The run continues either way -- the gate
    kills a *finding*, never the run.

    The other three outcomes are not refusals and are not recorded here:
    a passed or downgraded finding is shipped, and a chain-required
    finding is routed to the chain builder by the caller.
    """
    if not isinstance(finding, Finding):
        if isinstance(finding, Mapping):
            finding = Finding.from_mapping(finding)
        else:
            raise FindingGateError(
                "a Finding is required, got %r" % (type(finding).__name__,)
            )
    verdict = evaluate_finding(finding)
    decision = GateDecision(_ACTION_BY_OUTCOME[verdict.outcome], verdict, finding)
    if decision.held and registry is not None:
        _record_held_finding(
            registry,
            finding,
            verdict,
            grant_id=grant_id,
            action=action,
            subject=subject,
            now=now,
        )
    return decision


def _record_held_finding(
    registry: Any,
    finding: Finding,
    verdict: Verdict,
    *,
    grant_id: str,
    action: str,
    subject: str,
    now: Optional[float],
) -> None:
    """Record a killed finding as a refusal row through the existing seam.

    The refusal-hold wiring's registry records a :class:`RefusalRow`, which
    needs four evidence fields.  They are derived from the finding and the
    verdict -- there is no clock and no randomness here either:

    * the **evidence hash** is the finding's own digest;
    * the **ruleset hash** is the digest of the gate's question list, so a
      row says *which* gate held the finding;
    * the **population digest** is the digest of the accepted-impact list,
      so a row says *what the program accepts* at the time;
    * the **verifier key** is the gate itself.

    The refusal is recorded under the finding's own identity, so a held
    finding is traceable through the same ledger as every other refusal.
    """
    from refusal_row import record_refusal  # local import: keeps the module import-light

    ruleset_hash = _digest_of_text("|".join(QUESTIONS))
    population_digest = _digest_of_text("|".join(ACCEPTED_IMPACT_KINDS))
    row = record_refusal(
        verdict=verdict.outcome.lower().replace("-", "_"),
        evidence_hash=finding_digest(finding),
        ruleset_hash=ruleset_hash,
        verifier_key="finding-gate@b173",
        population_digest=population_digest,
        refused_at=int(now or 0),
        reason=verdict.reason,
        instruments=["finding-gate@b173", "refusal-hold@b173"],
    )
    registry.record(
        grant_id,
        action,
        subject,
        row=row,
        now=now,
    )


def _digest_of_text(text: str) -> str:
    """A stable digest of a piece of text."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
