# The finding gate: seven questions before a finding ships

**Slice:** `B173 bughunter-finding-gate`
**Module:** `components/northstar-agent-runtime/finding_gate.py`
**Tests:** `components/northstar-agent-runtime/tests/test_finding_gate.py`

## 1. Why this exists

Northstar's acceptance ledger (2026-11-15: 68 slices re-run, 32 pass / 36
fail) and the mutant probes keep producing **false kills**. A finding that
is not real is not a small cost: the judge and the mutant-evidence
machinery *trust* findings, so one false finding poisons acceptance, and a
poisoned acceptance ledger cannot be distinguished from a strict one by
reading it.

The runtime already had the machinery to **hold** something — the refusal
hold (`refusal_hold.py`, `refusal_hold_wiring.py`) holds a refusal and lets
the run continue — but nothing to decide whether a finding **deserves to be
shipped at all**. A finding was either reported or it was not; there was no
gate between "the tester saw something" and "the finding goes into the
ledger".

This slice adds that gate: a pure, deterministic function that asks a fixed
list of questions, in a fixed order, and kills a finding on the first "no".
**The gate kills findings, never the run.**

## 2. Source and attribution

The methodology is adapted from **Claude-BugHunter** by Sachin Sharma,
`triage-validation` skill:
<https://github.com/elementalsouls/Claude-BugHunter.git> (code MIT / content
CC BY 4.0).

What is taken from the source is the **shape**: a small ordered list of
questions, a pre-gate asked first, and the layer-ordering trap. What is
**not** taken is any code, any skill text, any payload table, or any wording:
the questions below are Northstar's own, the finding vocabulary is
Northstar's own, and the gate is a pure function of the finding.

Northstar extensions (explicitly **not** from the source) are listed in
§7.

## 3. The finding

A finding is a frozen dataclass (`finding_gate.Finding`) carrying exactly
what the questions need:

| field | question it answers |
| --- | --- |
| `attacker_steps` | q1 — the steps, written as **real HTTP requests** |
| `impact_kind` | q2 — the impact, checked against the accepted list |
| `in_scope_asset` | q3 — the asset the root cause lives in |
| `required_privilege` | q4 — the privilege the attack needs |
| `known_behavior` | q5 — is this already known or documented |
| `impact_proof` / `impact_proof_kind` | q6 — the proof, beyond "possible" |
| `minimal_body_resent` | q6 — the layer-ordering re-send |
| `never_submit` | q7 — the never-submit list |
| `attacker_can_act_now` | pre-gate — can the attacker act right now |
| `impact` | pre-gate — what the victim loses |
| `repro_minutes` | pre-gate — reproducible in ten minutes |
| `severity` | the severity step |
| `chain_required` | q6 — the impact needs a second step |
| `claims_auth_bypass` | q6 — the bypass claim, for the trap |
| `low_impact` | the severity step |

A mapping is accepted too (`Finding.from_mapping`), and an **unknown field
is refused** rather than ignored: a field the gate does not know about is a
field the gate does not check, and a silently dropped field is how a finding
gets shipped without a question having been asked.

## 4. The pre-gate (Gate 0)

Three questions, asked **before** the seven. Each is fatal: a finding that
fails any one of them is killed and the seven never run.

1. **Can the attacker act on this right now?** A finding that describes a
   future or theoretical capability is not a finding.
2. **What does the victim actually lose?** A finding that names no impact
   is killed: "something might be possible" is not a loss.
3. **Is it reproducible from scratch in ten minutes?** A finding whose
   reproduction is unknown, or slower than ten minutes, is killed.

The order inside the pre-gate is fixed, so the reason a finding was killed
is always the *first* thing wrong with it. The machine names are the ones
the gate uses in `finding_gate.GATE_0_QUESTIONS`:

| name | question |
| --- | --- |
| `gate-0-can-the-attacker-act-now` | can the attacker act on this right now? |
| `gate-0-what-does-the-victim-lose` | what does the victim actually lose? |
| `gate-0-is-it-reproducible-in-ten-minutes` | is it reproducible from scratch in ten minutes? |

## 5. The seven questions

Asked in order. The **first** "no" ends the assessment. The machine names
are the ones the gate uses in `finding_gate.QUESTIONS`; they are what a
verdict's `question` field carries when it names the step that produced the
answer.

| name | question |
| --- | --- |
| `q1-can-the-attacker-act-now` | Can an attacker use this right now, step by step? |
| `q2-is-the-impact-accepted` | Is the impact on the program's accepted impact list? |
| `q3-is-the-root-cause-in-scope` | Is the root cause in an in-scope asset? |
| `q4-is-the-privilege-available` | Does it work without privileged access an attacker cannot get? |
| `q5-is-it-new-behaviour` | Is this not already known or documented behaviour? |
| `q6-is-the-impact-proved` | Can impact be proved beyond "technically possible"? |
| `q7-is-it-submittable` | Is this not on the never-submit list? |

In words:

1. **Can an attacker use this right now, step by step?** The steps must be
   written as real requests — a method, a target, optionally a body. A step
   that cannot be sent is a step that cannot be carried out, so a prose
   step ("log in as the admin") kills the finding.
2. **Is the impact on the program's accepted impact list?** The accepted
   list is `finding_gate.ACCEPTED_IMPACT_KINDS` (authentication-bypass,
   authorization-bypass, code-execution, data-exposure, integrity,
   availability, sensitive-disclosure). A finding that names no impact
   kind is killed as well: it cannot be checked.
3. **Is the root cause in an in-scope asset?** A finding that names no
   asset cannot be placed, so it is killed.
4. **Does it work without privileged access an attacker cannot get?** The
   finding's `required_privilege` must be one of the unprivileged
   descriptors (`""`, `none`, `unprivileged`, …). Anything else — an
   administrator account, a cluster role — is a privilege the attacker
   cannot get, and the finding is killed.
5. **Is this not already known or documented behaviour?** A known behaviour
   is not a new finding.
6. **Can impact be proved beyond "technically possible"?** The proof must
   be concrete: a XSS finding shows the cookie being stolen, an SSRF
   finding shows an internal endpoint returning data. This is where the
   **layer-ordering trap** lives (§6).
7. **Is this not on the never-submit list?** A finding the program has
   declared never-submittable is killed.

## 6. The layer-ordering trap

**A validation error does not prove that authentication was passed.** A
global sanitiser or a body parser can reject a request *before* the
authentication middleware ever sees it. So a "bypass" demonstrated only by
a status code is usually a parser rejecting the request, not an
authorization hole.

The gate enforces this structurally, as three separate refusals:

* the only evidence is a **status code** → KILL;
* the only evidence is an **error response** → KILL;
* the finding **claims an authentication bypass** and no
  **minimal-well-formed-body re-send** is on record → KILL.

The re-send is the check that tells the two apart: a minimal, well-formed
body that still reaches the handler is a bypass; a malformed body that gets
a 400 is a parser doing its job.

## 7. Verdicts, and what is Northstar's own

| verdict | meaning | what happens to the finding |
| --- | --- | --- |
| `PASS` | it cleared the pre-gate and all seven questions | shipped as it stands |
| `KILL` | one question came back "no" | **held**, not shipped; the run continues |
| `CHAIN-REQUIRED` | the impact is real but needs a second step to prove | routed to the chain builder |
| `DOWNGRADE` | real, but the impact is low | shipped at a **lowered severity** |

The verdict vocabulary, the accepted-impact list, the in-scope-asset
notion, the structural enforcement of the layer-ordering trap, and the
wiring point are **Northstar's own** — the source kills or reports a
finding, and does not route one to a chain builder or lower its severity.

## 8. The wiring point

The gate is wired into the **existing refusal-hold seam** as a read-only
check: where a finding would be accepted, it goes through the gate first.

`finding_gate.apply_finding_gate(finding, registry=..., grant_id=...,
action=..., subject=...)` returns a `GateDecision`:

* `action == "hold"` — the finding is killed. When a refusal-hold
  `registry` is supplied, the killed finding is **recorded as a refusal
  row** through the registry's existing `record()` seam, so "held" is an
  auditable row rather than a silent drop. The refusal's four evidence
  fields are derived from the finding and the gate (the finding's own
  digest, the digest of the gate's question list, the digest of the
  accepted-impact list, and the gate as the verifier key) — no clock and no
  randomness.
* `action == "chain"` — the caller routes the finding to the chain builder.
* `action == "downgrade"` — the caller ships it at `verdict.severity`.
* `action == "ship"` — the caller ships it as it stands.

**A killed finding never stops the run.** The refusal hold's own
semantics are unchanged: the gate kills a *finding*, and the run
continues.

## 9. Purity

`evaluate_finding` is total and side-effect free: it reads nothing but its
argument, and it does no network access, no I/O, no clock read and no
randomness. The same finding yields the same verdict on every run, which
is what lets the mutant probe and the governance bench exercise it
deterministically. The test suite pins this both behaviourally (the same
finding yields the same verdict five times running) and structurally (the
module imports no clock, no randomness, no socket).
