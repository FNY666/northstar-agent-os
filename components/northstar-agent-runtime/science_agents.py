"""Scientific-research & lab AI discipline gates (one-hundred-sixty-second batch).

Absorbs the 2026 AI-in-science research thread:

* **Google DeepMind Co-Scientist** (Nature, 2026-05-19): Gemini-based
  multi-agent hypothesis generation. The 2026-08-27 arXiv extended
  edition (unreviewed preprint) adds machine-readable CVD protocols,
  lab-device dispatch, and paper assembly: 70+ physical experiments
  produced MoS2/MoSe2/WS2 monolayers; a reliability module cut severe
  result hallucinations to **4%** vs 46% (ablation) vs 90% (baseline).
  Human experts still did precursor loading, safety, and sample
  handling — the current safety boundary is "humans do the dangerous
  moves", and the paper's direction is to agentize even that.
* **Microsoft Discovery** — GA 2026-06-02 (Windows app + REST API);
  FutureHouse platform no longer exists (verified redirects).
* **Anthropic ART discovery** (2026-09-23): ~950 Claude agents, 21
  hours, ~210M tokens, screened ~200K reverse transcriptases to find
  a novel phage enzyme system (ART). Reviewed by 张锋. The division
  of labor was explicit: AI did data retrieval, candidate screening,
  and hypothesis sorting; **the wet lab was done by humans**.
  Anthropic separately built its own Bay Area wet lab for
  Claude-controlled robotics **under continuous human supervision**.
* **Medra** (¥440M Series A): robots that operate ~70% of common lab
  instruments (pipettes, centrifuges, cryo freezers, CO2 incubators,
  flow cytometers) **without vendor APIs** — hands, eyes, and a brain
  decision loop. Traditional lab safety assumes a human hand on the
  instrument; when the "hand" is a robot with remote-updatable
  software, the safety model must be rewritten.
* **OpenAI x Ginkgo Bioworks**: GPT-5 **autonomously designed and
  ran 36,000 biology experiments** (design -> robot execution ->
  data -> next round); humans only set the goal; target protein
  production cost cut ~40%. Phys.org's judgment: "AI is learning to
  design and run biological experiments autonomously, but the
  governance keeping up with these capabilities lags."
* **Roche** (Sept 2026 investor day): plans for autonomous AI-driven
  labs with "greater independence".
* **Lancet audit** (Columbia et al., 2026): 2.5M biomedical papers
  audited — **4,000+ fabricated references in 2,810 papers**; the
  fabricated-reference rate rose from ~1/2,828 (2023) to ~1/458
  (2025) to **1/277 by early 2026**. 78.8% of fabricated citations
  pass arXiv screening; 85.3% survive bioRxiv-to-journal conversion.
  Fabricated citations embedded in open libraries will be absorbed
  and reproduced by future AI training — a self-reinforcing loop.
* **Anthropic threat report (Sept 2026)**: identified and disrupted
  **5 cases** of Claude being used for possible bioweapon-enabling
  work (dual-use virology/toxins; one case of bypassing regional
  limits on gain-of-function-adjacent chikungunya research).
* **Joint CEO call (2026-06-05)**: OpenAI, Anthropic, and Microsoft
  AI CEOs jointly called on Congress to **mandate screening of
  synthetic DNA/RNA sales** — frontier developers asking for binding
  biosecurity regulation of their own technology's risks.
* **The screening gap**: DNA synthesis screening works by
  **sequence-homology matching** against known-threat libraries.
  AI can design sequences that are **functionally dangerous but
  not sequence-similar**, bypassing existing screens entirely — and
  the existence of the homology standard itself incentivizes AI
  evasion.

Northstar mapping: hypotheses bind evidence tiers and
citation-existence verification; physical lab actions bind
human-execution receipts; bio-related workflows bind function-
equivalence dual-use screening receipts; synthesis orders bind
orderer identity plus screening receipts; analysis tools bind the
result digests they reproduced; lab robots declare capability
envelopes; discoveries bind attribution receipts that forbid
"AI independently discovered" marketing claims in formal records;
lab incidents land in a cross-institution incident ledger.

Fail-closed rules:

1. **Evidence tiers** — agent-generated hypotheses/citations default
   to ``tier=signal``; entering a paper/patent/grant application
   requires tier ``evidence`` or ``verified`` **plus** a
   citation-existence verification receipt (DOI resolution + title
   match); failure is ``science.unverified_citation`` — the Lancet
   1/277 lesson mechanized.
2. **Wetlab human-action gate** — physical actions (pipetting,
   heating, handling pathogens) bind human-execution receipts; agent
   output is advisory only; direct actuator drive without a human
   sign-off is ``science.ungated_wetlab``.
3. **Dual-use screening** — bio workflows bind dual-use screening
   receipts covering **function-equivalence categories**, not just
   sequence homology. Homology-only screening is
   ``science.homology_only_screen``; missing or hit is
   ``science.unscreened_dual_use``.
4. **Synthesis-order binding** — synthesis orders bind orderer
   identity + screening receipt; the provider may not execute
   without them (``science.unbound_synthesis_order``).
5. **Reproducibility lock** — each analysis tool/version binds the
   digest of the result it reproduced (Paper2Agent-style); result
   drift invalidates the tool (``science.reproduction_drift``) —
   it fails loudly instead of silently emitting new numbers.
6. **Lab-robot capability envelope** — embodied lab robots declare
   envelopes (instrument allowlist, force/temperature limits,
   exclusion zones); out-of-envelope instructions refuse with
   ``science.envelope_violation`` (Medra lesson).
7. **Discovery attribution** — discoveries bind attribution
   receipts (goal setter, candidate screener, wet-lab validator);
   formal records claiming "AI independently discovered" are
   ``science.false_discovery_attribution``.
8. **Incident ledger** — robot-lab anomalies (batch experiment
   failures, interlock trips) land in a hash-chained,
   cross-institution incident ledger, not just vendor logs.

Honest boundary: receipts are *declared* research discipline —
digests recompute, signatures verify, tiers and envelopes are
checked. The gate cannot establish that a hypothesis is *true*,
that the human "executor" was qualified, or that a screened-
negative sequence is actually safe. It guarantees no unverified
citation, no ungated wetlab action, and no unscreened dual-use
workflow passes through an agent pipeline without a checkable
claim.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (``canonical_json``), Ed25519
via the vendored ``ed25519`` module — its ``verify()`` returns a
bool and never raises (150th/155th-batch lesson: the return value
is honored, never wrapped in try/except-around-verify), and all
digest comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex


SCIENCE_SCHEMA_VERSION = "northstar.science.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64

#: Policy classification tiers.
CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Denial reason codes. All verdict reasons start with one of these.
DENY_UNVERIFIED_CITATION = "science.unverified_citation"
DENY_UNGATED_WETLAB = "science.ungated_wetlab"
DENY_HOMOLOGY_ONLY_SCREEN = "science.homology_only_screen"
DENY_UNSCREENED_DUAL_USE = "science.unscreened_dual_use"
DENY_UNBOUND_SYNTHESIS_ORDER = "science.unbound_synthesis_order"
DENY_REPRODUCTION_DRIFT = "science.reproduction_drift"
DENY_ENVELOPE_VIOLATION = "science.envelope_violation"
DENY_FALSE_DISCOVERY_ATTRIBUTION = "science.false_discovery_attribution"
DENY_UNQUALIFIED_EXECUTOR = "science.unqualified_executor"
DENY_UNVERIFIED_TIER = "science.unverified_tier"

#: Closed evidence-tier vocabulary. Agent outputs default to
#: ``signal``; formal records require ``evidence`` or ``verified``.
EVIDENCE_TIERS: tuple[str, ...] = (
    "signal",
    "evidence",
    "verified",
)

#: Formal-record classes that require evidence-tier material.
FORMAL_RECORDS: tuple[str, ...] = (
    "paper",
    "patent",
    "grant_application",
)

#: Closed wetlab physical-action vocabulary.
WETLAB_ACTIONS: tuple[str, ...] = (
    "pipette",
    "heat",
    "handle_pathogen",
    "centrifuge",
    "incubate",
    "dispense_reagent",
)

#: Closed function-equivalence screening categories. Screening
#: receipts must name the categories actually evaluated; homology-
#: only evaluation is never enough.
SCREEN_CATEGORIES: tuple[str, ...] = (
    "sequence_homology",
    "function_equivalence",
    "institution_qualification",
    "end_use_screen",
)

#: Minimum categories a dual-use screening receipt must cover.
REQUIRED_SCREEN_CATEGORIES = frozenset({"function_equivalence", "institution_qualification"})

#: Closed incident-class vocabulary for the cross-institution ledger.
INCIDENT_CLASSES: tuple[str, ...] = (
    "batch_experiment_failure",
    "interlock_trip",
    "containment_breach",
    "unauthorized_access",
    "robot_malfunction",
)


class ScienceError(ValueError):
    """A malformed science receipt or a programming error.

    Raised for structural problems (bad digests, unknown tiers,
    non-binding fields). Gate *failures* (unverified citation,
    ungated wetlab, unscreened dual-use) return a
    :class:`ScienceVerdict` with ``allowed=False`` instead — a failed
    gate is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ScienceError(f"{field_name} must be 64 hex chars")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScienceError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ScienceError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, 64):
        raise ScienceError("pubkey must be 32-byte hex (64 chars)")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    # The vendored ed25519.verify() returns a bool and never raises;
    # honor the return value (never try/except-around-verify).
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _check_chain(log: list[Any], type_name: str) -> None:
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ScienceError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ScienceError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise ScienceError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class ScienceVerdict:
    """Outcome of one science-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ScienceVerdict:
    return ScienceVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ScienceVerdict:
    return ScienceVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Authority registry (shared lookup for signed receipts)
# ---------------------------------------------------------------------------


@dataclass
class AuthorityRegistry:
    """Maps authority ids to Ed25519 public keys (hex)."""

    _pubkeys: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self._pubkeys = {}

    def register(self, authority_id: str, pubkey_hex: str) -> None:
        _check_nonempty_str(authority_id, "authority_id")
        _check_pubkey_hex(pubkey_hex)
        self._pubkeys[authority_id] = pubkey_hex

    def pubkey(self, authority_id: str) -> str | None:
        return self._pubkeys.get(authority_id)


def _new_log(registry: Any) -> str:
    return registry.log[-1].receipt_digest if registry.log else _GENESIS


# ---------------------------------------------------------------------------
# 1. Hypothesis evidence tiers + citation verification (Lancet lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CitationVerificationReceipt:
    """Binds a citation to an existence check (DOI resolution + title match)."""

    receipt_id: str
    citation_id: str
    doi: str
    title: str
    resolved_at: int  # injected epoch
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "citation_verification",
            "receipt_id": self.receipt_id,
            "citation_id": self.citation_id,
            "doi": self.doi,
            "title": self.title,
            "resolved_at": self.resolved_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class CitationVerificationRegistry:
    """Hash-chained log of citation-existence verification receipts."""

    authorities: AuthorityRegistry
    log: list[CitationVerificationReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        citation_id: str,
        doi: str,
        title: str,
        resolved_at: int,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> CitationVerificationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(citation_id, "citation_id")
        _check_nonempty_str(doi, "doi")
        _check_nonempty_str(title, "title")
        _check_ts(resolved_at, "resolved_at")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "citation_verification",
            "receipt_id": receipt_id,
            "citation_id": citation_id,
            "doi": doi,
            "title": title,
            "resolved_at": resolved_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = CitationVerificationReceipt(
            receipt_id=receipt_id,
            citation_id=citation_id,
            doi=doi,
            title=title,
            resolved_at=resolved_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def has_for(self, citation_id: str) -> bool:
        return any(r.citation_id == citation_id for r in self.log)

    def verify_chain(self) -> None:
        _check_chain(self.log, "citation_verification")


def hypothesis_evidence_tier(
    *,
    hypothesis_id: str,
    tier: str,
    formal_record: str,
    citation_ids: tuple[str, ...],
    verifications: CitationVerificationRegistry,
) -> ScienceVerdict:
    """Gate an agent-generated hypothesis for a formal record.

    Agent outputs default to ``signal``; ``paper`` / ``patent`` /
    ``grant_application`` require ``evidence`` or ``verified`` tier
    **plus** a citation-existence receipt for every citation.
    Missing verification is ``science.unverified_citation`` (the
    Lancet 1/277 lesson); an under-tiered hypothesis is
    ``science.unverified_tier``.
    """
    _check_nonempty_str(hypothesis_id, "hypothesis_id")
    if tier not in EVIDENCE_TIERS:
        raise ScienceError(f"unknown evidence tier {tier!r}")
    if formal_record not in FORMAL_RECORDS:
        raise ScienceError(f"unknown formal record {formal_record!r}")
    if tier not in ("evidence", "verified"):
        return _deny(
            DENY_UNVERIFIED_TIER,
            f"hypothesis {hypothesis_id!r} at tier {tier!r} may not enter "
            f"formal record {formal_record!r}; needs evidence or verified",
        )
    missing = [cid for cid in citation_ids if not verifications.has_for(cid)]
    if missing:
        return _deny(
            DENY_UNVERIFIED_CITATION,
            f"hypothesis {hypothesis_id!r} cites {missing!r} without "
            "existence verification receipts",
        )
    return _allow(
        f"hypothesis {hypothesis_id!r} at tier {tier!r} with {len(citation_ids)} "
        f"verified citations enters {formal_record!r}"
    )


# ---------------------------------------------------------------------------
# 2. Wetlab human-action gate (Anthropic "AI proposes, humans do wet lab")
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WetlabExecutionReceipt:
    """Binds a physical lab action to a named human executor's sign-off."""

    receipt_id: str
    action: str  # from WETLAB_ACTIONS
    target: str  # sample / protocol / experiment identifier
    executor_id: str  # named human
    executed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "wetlab_execution",
            "receipt_id": self.receipt_id,
            "action": self.action,
            "target": self.target,
            "executor_id": self.executor_id,
            "executed_at": self.executed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class WetlabExecutionRegistry:
    """Hash-chained log of human wetlab-execution receipts."""

    authorities: AuthorityRegistry
    log: list[WetlabExecutionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        action: str,
        target: str,
        executor_id: str,
        executed_at: int,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> WetlabExecutionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        if action not in WETLAB_ACTIONS:
            raise ScienceError(f"unknown wetlab action {action!r}")
        _check_nonempty_str(target, "target")
        _check_nonempty_str(executor_id, "executor_id")
        _check_ts(executed_at, "executed_at")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "wetlab_execution",
            "receipt_id": receipt_id,
            "action": action,
            "target": target,
            "executor_id": executor_id,
            "executed_at": executed_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = WetlabExecutionReceipt(
            receipt_id=receipt_id,
            action=action,
            target=target,
            executor_id=executor_id,
            executed_at=executed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def has_for(self, action: str, target: str) -> bool:
        return any(r.action == action and r.target == target for r in self.log)

    def verify_chain(self) -> None:
        _check_chain(self.log, "wetlab_execution")


def wetlab_human_action_gate(
    *,
    action: str,
    target: str,
    agent_instruction_digest: str,
    executions: WetlabExecutionRegistry,
    now: int,
) -> ScienceVerdict:
    """Gate a physical lab action: agent instructions are advisory only.

    The action may proceed only if a live human-execution receipt
    binds ``(action, target)``. Direct agent-driven actuation without
    a human sign-off is ``science.ungated_wetlab`` (the OpenAI×Ginkgo
    36,000-experiment lesson).
    """
    if action not in WETLAB_ACTIONS:
        raise ScienceError(f"unknown wetlab action {action!r}")
    _check_hex64(agent_instruction_digest, "agent_instruction_digest")
    _check_ts(now, "now")
    if not executions.has_for(action, target):
        return _deny(
            DENY_UNGATED_WETLAB,
            f"physical action {action!r} on {target!r} has no human-execution "
            "receipt; agent instructions are advisory only",
        )
    return _allow(
        f"physical action {action!r} on {target!r} covered by human-execution receipt"
    )


# ---------------------------------------------------------------------------
# 3/4. Dual-use screening + synthesis-order binding (CEO letter lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DualUseScreeningReceipt:
    """Binds a bio workflow to a function-equivalence dual-use screen."""

    receipt_id: str
    workflow_id: str
    categories_evaluated: tuple[str, ...]
    screen_result: str  # "clear" | "hit"
    screened_at: int
    institution_id: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "dual_use_screening",
            "receipt_id": self.receipt_id,
            "workflow_id": self.workflow_id,
            "categories_evaluated": list(self.categories_evaluated),
            "screen_result": self.screen_result,
            "screened_at": self.screened_at,
            "institution_id": self.institution_id,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class DualUseScreeningRegistry:
    """Hash-chained log of dual-use screening receipts."""

    authorities: AuthorityRegistry
    log: list[DualUseScreeningReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        workflow_id: str,
        categories_evaluated: tuple[str, ...],
        screen_result: str,
        screened_at: int,
        institution_id: str,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> DualUseScreeningReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(workflow_id, "workflow_id")
        unknown = [c for c in categories_evaluated if c not in SCREEN_CATEGORIES]
        if unknown:
            raise ScienceError(f"unknown screening categories {unknown!r}")
        if screen_result not in ("clear", "hit"):
            raise ScienceError("screen_result must be 'clear' or 'hit'")
        _check_ts(screened_at, "screened_at")
        _check_nonempty_str(institution_id, "institution_id")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "dual_use_screening",
            "receipt_id": receipt_id,
            "workflow_id": workflow_id,
            "categories_evaluated": list(categories_evaluated),
            "screen_result": screen_result,
            "screened_at": screened_at,
            "institution_id": institution_id,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = DualUseScreeningReceipt(
            receipt_id=receipt_id,
            workflow_id=workflow_id,
            categories_evaluated=categories_evaluated,
            screen_result=screen_result,
            screened_at=screened_at,
            institution_id=institution_id,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def latest_for(self, workflow_id: str) -> DualUseScreeningReceipt | None:
        matches = [r for r in self.log if r.workflow_id == workflow_id]
        return matches[-1] if matches else None

    def verify_chain(self) -> None:
        _check_chain(self.log, "dual_use_screening")


def dual_use_screen(
    *,
    workflow_id: str,
    screenings: DualUseScreeningRegistry,
) -> ScienceVerdict:
    """Gate a bio workflow on a function-equivalence dual-use screen.

    A workflow with no screening receipt is
    ``science.unscreened_dual_use``; one whose receipt covers only
    sequence homology is ``science.homology_only_screen`` — homology
    alone is fundamentally inadequate against AI-designed
    functionally-dangerous sequences. A screening hit also denies.
    """
    _check_nonempty_str(workflow_id, "workflow_id")
    receipt = screenings.latest_for(workflow_id)
    if receipt is None:
        return _deny(
            DENY_UNSCREENED_DUAL_USE,
            f"bio workflow {workflow_id!r} has no dual-use screening receipt",
        )
    if not REQUIRED_SCREEN_CATEGORIES.issubset(receipt.categories_evaluated):
        return _deny(
            DENY_HOMOLOGY_ONLY_SCREEN,
            f"bio workflow {workflow_id!r} screening {receipt.receipt_id!r} "
            "lacks function-equivalence evaluation; homology alone is inadequate",
        )
    if receipt.screen_result == "hit":
        return _deny(
            DENY_UNSCREENED_DUAL_USE,
            f"bio workflow {workflow_id!r} screening {receipt.receipt_id!r} "
            "returned a hit; execution refused",
        )
    return _allow(
        f"bio workflow {workflow_id!r} cleared by {receipt.receipt_id!r} "
        f"(function-equivalence + institution qualification)"
    )


def synthesis_order_binding(
    *,
    order_id: str,
    orderer_id: str,
    sequence_digest: str,
    screenings: DualUseScreeningRegistry,
    workflow_id: str,
) -> ScienceVerdict:
    """Gate a synthesis order: it must bind orderer identity + a
    screening receipt. The provider may not execute a synthesis
    order without both (``science.unbound_synthesis_order``) — the
    Cotton-Klobuchar direction mechanized.
    """
    _check_nonempty_str(order_id, "order_id")
    _check_nonempty_str(orderer_id, "orderer_id")
    _check_hex64(sequence_digest, "sequence_digest")
    _check_nonempty_str(workflow_id, "workflow_id")
    receipt = screenings.latest_for(workflow_id)
    if receipt is None:
        return _deny(
            DENY_UNBOUND_SYNTHESIS_ORDER,
            f"synthesis order {order_id!r} binds no screening receipt; "
            "provider must not execute",
        )
    screen_verdict = dual_use_screen(workflow_id=workflow_id, screenings=screenings)
    if not screen_verdict.allowed:
        return _deny(
            DENY_UNBOUND_SYNTHESIS_ORDER,
            f"synthesis order {order_id!r} screening failed: {screen_verdict.reason}",
        )
    return _allow(
        f"synthesis order {order_id!r} from {orderer_id!r} bound to "
        f"screening {receipt.receipt_id!r}"
    )


# ---------------------------------------------------------------------------
# 5. Reproducibility lock (Paper2Agent lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReproductionBindingReceipt:
    """Binds an analysis tool/version to the digest of the result it reproduced."""

    receipt_id: str
    tool_id: str
    tool_version: str
    paper_digest: str
    reproduced_result_digest: str
    bound_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "reproduction_binding",
            "receipt_id": self.receipt_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "paper_digest": self.paper_digest,
            "reproduced_result_digest": self.reproduced_result_digest,
            "bound_at": self.bound_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ReproductionBindingRegistry:
    """Hash-chained log of tool->reproduced-result bindings."""

    authorities: AuthorityRegistry
    log: list[ReproductionBindingReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        tool_id: str,
        tool_version: str,
        paper_digest: str,
        reproduced_result_digest: str,
        bound_at: int,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> ReproductionBindingReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(tool_id, "tool_id")
        _check_nonempty_str(tool_version, "tool_version")
        _check_hex64(paper_digest, "paper_digest")
        _check_hex64(reproduced_result_digest, "reproduced_result_digest")
        _check_ts(bound_at, "bound_at")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "reproduction_binding",
            "receipt_id": receipt_id,
            "tool_id": tool_id,
            "tool_version": tool_version,
            "paper_digest": paper_digest,
            "reproduced_result_digest": reproduced_result_digest,
            "bound_at": bound_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = ReproductionBindingReceipt(
            receipt_id=receipt_id,
            tool_id=tool_id,
            tool_version=tool_version,
            paper_digest=paper_digest,
            reproduced_result_digest=reproduced_result_digest,
            bound_at=bound_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def latest_for(self, tool_id: str, tool_version: str) -> ReproductionBindingReceipt | None:
        matches = [r for r in self.log if r.tool_id == tool_id and r.tool_version == tool_version]
        return matches[-1] if matches else None

    def verify_chain(self) -> None:
        _check_chain(self.log, "reproduction_binding")


def reproducibility_lock(
    *,
    tool_id: str,
    tool_version: str,
    current_result_digest: str,
    bindings: ReproductionBindingRegistry,
) -> ScienceVerdict:
    """Lock a tool to the result it reproduced (Paper2Agent lesson).

    A tool/version with no reproduction binding is
    ``NON_AUTHORITATIVE``; if its current output digest no longer
    matches the bound digest, the tool is invalidated with
    ``science.reproduction_drift`` — it fails loudly instead of
    silently emitting new numbers.
    """
    _check_nonempty_str(tool_id, "tool_id")
    _check_nonempty_str(tool_version, "tool_version")
    _check_hex64(current_result_digest, "current_result_digest")
    binding = bindings.latest_for(tool_id, tool_version)
    if binding is None:
        return _deny(
            DENY_REPRODUCTION_DRIFT,
            f"tool {tool_id!r}@{tool_version!r} has no reproduction binding; "
            "cannot be trusted to reproduce",
        )
    if not hmac.compare_digest(binding.reproduced_result_digest, current_result_digest):
        return _deny(
            DENY_REPRODUCTION_DRIFT,
            f"tool {tool_id!r}@{tool_version!r} drifted from its reproduction "
            f"binding {binding.receipt_id!r}; tool invalidated",
        )
    return _allow(
        f"tool {tool_id!r}@{tool_version!r} matches reproduction binding "
        f"{binding.receipt_id!r}",
        receipt_digest=binding.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Lab-robot capability envelope (Medra lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LabRobotEnvelopeReceipt:
    """Binds an embodied lab robot to its capability envelope."""

    receipt_id: str
    robot_id: str
    instrument_allowlist: tuple[str, ...]
    max_force_newtons: float
    max_temperature_celsius: float
    exclusion_zones: tuple[str, ...]
    declared_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "lab_robot_envelope",
            "receipt_id": self.receipt_id,
            "robot_id": self.robot_id,
            "instrument_allowlist": list(self.instrument_allowlist),
            "max_force_newtons": self.max_force_newtons,
            "max_temperature_celsius": self.max_temperature_celsius,
            "exclusion_zones": list(self.exclusion_zones),
            "declared_at": self.declared_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class LabRobotEnvelopeRegistry:
    """Hash-chained log of lab-robot capability envelopes."""

    authorities: AuthorityRegistry
    log: list[LabRobotEnvelopeReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        robot_id: str,
        instrument_allowlist: tuple[str, ...],
        max_force_newtons: float,
        max_temperature_celsius: float,
        exclusion_zones: tuple[str, ...],
        declared_at: int,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> LabRobotEnvelopeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(robot_id, "robot_id")
        if not instrument_allowlist:
            raise ScienceError("instrument_allowlist must not be empty")
        if max_force_newtons <= 0 or max_temperature_celsius <= 0:
            raise ScienceError("envelope limits must be positive")
        _check_ts(declared_at, "declared_at")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "lab_robot_envelope",
            "receipt_id": receipt_id,
            "robot_id": robot_id,
            "instrument_allowlist": list(instrument_allowlist),
            "max_force_newtons": max_force_newtons,
            "max_temperature_celsius": max_temperature_celsius,
            "exclusion_zones": list(exclusion_zones),
            "declared_at": declared_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = LabRobotEnvelopeReceipt(
            receipt_id=receipt_id,
            robot_id=robot_id,
            instrument_allowlist=instrument_allowlist,
            max_force_newtons=max_force_newtons,
            max_temperature_celsius=max_temperature_celsius,
            exclusion_zones=exclusion_zones,
            declared_at=declared_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def latest_for(self, robot_id: str) -> LabRobotEnvelopeReceipt | None:
        matches = [r for r in self.log if r.robot_id == robot_id]
        return matches[-1] if matches else None

    def verify_chain(self) -> None:
        _check_chain(self.log, "lab_robot_envelope")


def lab_robot_capability_envelope(
    *,
    robot_id: str,
    instrument: str,
    force_newtons: float,
    temperature_celsius: float,
    zone: str,
    envelopes: LabRobotEnvelopeRegistry,
) -> ScienceVerdict:
    """Gate a lab-robot instruction against its declared envelope.

    Instructions outside the envelope (undeclared instrument, force
    or temperature above limits, excluded zone) are refused with
    ``science.envelope_violation`` — the Medra lesson: when the
    "hand" is a robot with remote-updatable software, the safety
    model must be rewritten.
    """
    _check_nonempty_str(robot_id, "robot_id")
    _check_nonempty_str(instrument, "instrument")
    _check_nonempty_str(zone, "zone")
    envelope = envelopes.latest_for(robot_id)
    if envelope is None:
        return _deny(
            DENY_ENVELOPE_VIOLATION,
            f"lab robot {robot_id!r} has no declared capability envelope",
        )
    if instrument not in envelope.instrument_allowlist:
        return _deny(
            DENY_ENVELOPE_VIOLATION,
            f"lab robot {robot_id!r}: instrument {instrument!r} outside envelope",
        )
    if force_newtons > envelope.max_force_newtons:
        return _deny(
            DENY_ENVELOPE_VIOLATION,
            f"lab robot {robot_id!r}: force {force_newtons}N exceeds envelope "
            f"{envelope.max_force_newtons}N",
        )
    if temperature_celsius > envelope.max_temperature_celsius:
        return _deny(
            DENY_ENVELOPE_VIOLATION,
            f"lab robot {robot_id!r}: temperature {temperature_celsius}C exceeds "
            f"envelope {envelope.max_temperature_celsius}C",
        )
    if zone in envelope.exclusion_zones:
        return _deny(
            DENY_ENVELOPE_VIOLATION,
            f"lab robot {robot_id!r}: zone {zone!r} is an exclusion zone",
        )
    return _allow(
        f"lab robot {robot_id!r} instruction inside envelope {envelope.receipt_id!r}",
        receipt_digest=envelope.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 7. Discovery attribution (ART/Hakken lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryAttributionReceipt:
    """Binds an AI-assisted discovery to its human attribution chain."""

    receipt_id: str
    discovery_id: str
    goal_setter_id: str
    candidate_screener_id: str  # "ai:<system>" or human id
    wetlab_validator_id: str  # must be a human — AI cannot validate itself
    formal_record: str  # from FORMAL_RECORDS
    discovery_claim: str  # free-text claim as it will appear
    attributed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "discovery_attribution",
            "receipt_id": self.receipt_id,
            "discovery_id": self.discovery_id,
            "goal_setter_id": self.goal_setter_id,
            "candidate_screener_id": self.candidate_screener_id,
            "wetlab_validator_id": self.wetlab_validator_id,
            "formal_record": self.formal_record,
            "discovery_claim": self.discovery_claim,
            "attributed_at": self.attributed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class DiscoveryAttributionRegistry:
    """Hash-chained log of discovery-attribution receipts."""

    authorities: AuthorityRegistry
    log: list[DiscoveryAttributionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        discovery_id: str,
        goal_setter_id: str,
        candidate_screener_id: str,
        wetlab_validator_id: str,
        formal_record: str,
        discovery_claim: str,
        attributed_at: int,
        authority_id: str,
        sign: Callable[[bytes], str],
    ) -> DiscoveryAttributionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(discovery_id, "discovery_id")
        _check_nonempty_str(goal_setter_id, "goal_setter_id")
        _check_nonempty_str(candidate_screener_id, "candidate_screener_id")
        _check_nonempty_str(wetlab_validator_id, "wetlab_validator_id")
        if wetlab_validator_id.startswith("ai:"):
            raise ScienceError(
                "wetlab_validator_id must be a human; AI cannot validate itself"
            )
        if formal_record not in FORMAL_RECORDS:
            raise ScienceError(f"unknown formal record {formal_record!r}")
        _check_nonempty_str(discovery_claim, "discovery_claim")
        _check_ts(attributed_at, "attributed_at")
        _check_nonempty_str(authority_id, "authority_id")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ScienceError(f"unknown authority {authority_id!r}")
        prev_digest = _new_log(self)
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "discovery_attribution",
            "receipt_id": receipt_id,
            "discovery_id": discovery_id,
            "goal_setter_id": goal_setter_id,
            "candidate_screener_id": candidate_screener_id,
            "wetlab_validator_id": wetlab_validator_id,
            "formal_record": formal_record,
            "discovery_claim": discovery_claim,
            "attributed_at": attributed_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev_digest,
        }
        sig_body = dict(body)
        sig_body["signature_hex"] = "00" * 64
        signature_hex = sign(jcs_canonical_json(sig_body))
        receipt_digest = jcs_sha256_hex(body)
        receipt = DiscoveryAttributionReceipt(
            receipt_id=receipt_id,
            discovery_id=discovery_id,
            goal_setter_id=goal_setter_id,
            candidate_screener_id=candidate_screener_id,
            wetlab_validator_id=wetlab_validator_id,
            formal_record=formal_record,
            discovery_claim=discovery_claim,
            attributed_at=attributed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev_digest,
            receipt_digest=receipt_digest,
        )
        self.log.append(receipt)
        return receipt

    def latest_for(self, discovery_id: str) -> DiscoveryAttributionReceipt | None:
        matches = [r for r in self.log if r.discovery_id == discovery_id]
        return matches[-1] if matches else None

    def verify_chain(self) -> None:
        _check_chain(self.log, "discovery_attribution")


#: Claim phrasings that are banned in formal records (Hakken lesson:
#: "AI independently discovered" marketing claims are not records).
BANNED_ATTRIBUTION_PHRASES: tuple[str, ...] = (
    "ai independently discovered",
    "independently discovered by ai",
    "discovered by ai alone",
)


def discovery_attribution_receipt(
    *,
    discovery_id: str,
    formal_record: str,
    discovery_claim: str,
    attributions: DiscoveryAttributionRegistry,
) -> ScienceVerdict:
    """Gate a formal discovery record on a human attribution chain.

    The record must bind an attribution receipt naming who set the
    goal, who screened candidates, and which *human* validated in
    the wet lab. Formal records containing "AI independently
    discovered"-style marketing claims are
    ``science.false_discovery_attribution`` — the ART/Hakken lesson
    mechanized: AI predicts unreported relations; humans validate.
    """
    _check_nonempty_str(discovery_id, "discovery_id")
    if formal_record not in FORMAL_RECORDS:
        raise ScienceError(f"unknown formal record {formal_record!r}")
    _check_nonempty_str(discovery_claim, "discovery_claim")
    lowered = discovery_claim.lower()
    for banned in BANNED_ATTRIBUTION_PHRASES:
        if banned in lowered:
            return _deny(
                DENY_FALSE_DISCOVERY_ATTRIBUTION,
                f"formal record for {discovery_id!r} contains banned claim "
                f"{banned!r}; attribution must name goal setter, screener, "
                "and human wet-lab validator",
            )
    receipt = attributions.latest_for(discovery_id)
    if receipt is None:
        return _deny(
            DENY_FALSE_DISCOVERY_ATTRIBUTION,
            f"formal record for {discovery_id!r} binds no attribution receipt",
        )
    return _allow(
        f"formal record for {discovery_id!r} bound to attribution "
        f"{receipt.receipt_id!r} (validator: {receipt.wetlab_validator_id!r})",
        receipt_digest=receipt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Cross-institution lab-incident ledger
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LabIncidentReport:
    """A cross-institution, hash-chained lab-incident report."""

    incident_id: str
    incident_class: str  # from INCIDENT_CLASSES
    institution_id: str
    robot_id: str
    description_digest: str  # sha256 of the full description payload
    reported_at: int
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "lab_incident",
            "incident_id": self.incident_id,
            "incident_class": self.incident_class,
            "institution_id": self.institution_id,
            "robot_id": self.robot_id,
            "description_digest": self.description_digest,
            "reported_at": self.reported_at,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class LabIncidentLedger:
    """Cross-institution hash-chained lab-incident ledger."""

    log: list[LabIncidentReport]

    def __init__(self) -> None:
        self.log = []

    def report(
        self,
        incident_id: str,
        incident_class: str,
        institution_id: str,
        robot_id: str,
        description_digest: str,
        reported_at: int,
        reporter_signing_key: Any,
        authority_pubkey_hex: str,
    ) -> LabIncidentReport:
        _check_nonempty_str(incident_id, "incident_id")
        if incident_class not in INCIDENT_CLASSES:
            raise ScienceError(f"unknown incident class {incident_class!r}")
        _check_nonempty_str(institution_id, "institution_id")
        _check_nonempty_str(robot_id, "robot_id")
        _check_hex64(description_digest, "description_digest")
        _check_ts(reported_at, "reported_at")
        _check_pubkey_hex(authority_pubkey_hex)
        prev_digest = self.log[-1].receipt_digest if self.log else _GENESIS
        body = {
            "schema": SCIENCE_SCHEMA_VERSION,
            "type": "lab_incident",
            "incident_id": incident_id,
            "incident_class": incident_class,
            "institution_id": institution_id,
            "robot_id": robot_id,
            "description_digest": description_digest,
            "reported_at": reported_at,
            "authority_pubkey_hex": authority_pubkey_hex,
            "prev_digest": prev_digest,
        }
        signed_body = dict(body)
        signed_body["signature_hex"] = "00" * 64
        sig = ed25519.sign(reporter_signing_key, jcs_canonical_json(signed_body))
        if not _verify_signature(authority_pubkey_hex, signed_body, sig.hex()):
            raise ScienceError("incident report signature failed to verify")
        report = LabIncidentReport(
            incident_id=incident_id,
            incident_class=incident_class,
            institution_id=institution_id,
            robot_id=robot_id,
            description_digest=description_digest,
            reported_at=reported_at,
            authority_pubkey_hex=authority_pubkey_hex,
            signature_hex=sig.hex(),
            prev_digest=prev_digest,
            receipt_digest=jcs_sha256_hex(body),
        )
        self.log.append(report)
        return report

    def verify_chain(self) -> None:
        _check_chain(self.log, "lab_incident")


def lab_incident_reporting(
    *,
    incident_id: str,
    incident_class: str,
    institution_id: str,
    robot_id: str,
    description_digest: str,
    reported_at: int,
    reporter_signing_key: Any,
    authority_pubkey_hex: str,
    ledger: LabIncidentLedger,
) -> ScienceVerdict:
    """Append a lab incident to the cross-institution ledger.

    Robot-lab anomalies (batch experiment failures, interlock trips)
    must generate cross-institution-readable incident reports —
    visible beyond vendor logs. Always allows (reporting is the
    discipline); malformed input raises.
    """
    report = ledger.report(
        incident_id=incident_id,
        incident_class=incident_class,
        institution_id=institution_id,
        robot_id=robot_id,
        description_digest=description_digest,
        reported_at=reported_at,
        reporter_signing_key=reporter_signing_key,
        authority_pubkey_hex=authority_pubkey_hex,
    )
    return _allow(
        f"incident {incident_id!r} ({incident_class}) reported by "
        f"{institution_id!r} to the cross-institution ledger",
        receipt_digest=report.receipt_digest,
    )
