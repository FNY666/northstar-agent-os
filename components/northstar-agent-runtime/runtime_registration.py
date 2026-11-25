"""Single source of truth for runtime module registration.

Every module of this component must be *installed* -- otherwise it works in
the checkout and disappears after ``pip install .``.  There are two
installation mechanisms, and the registry covers both:

  * the flat modules, through ``pyproject.toml``'s
    ``[tool.setuptools] py-modules`` array;
  * the package members, through ``[tool.setuptools.packages.find]``'s
    ``include`` patterns -- a package's members cannot appear in
    ``py-modules`` at all, because that array lists flat names only.

The guarantee is asserted by ``tests/test_module_layout.py``; this module
is the other half: a declarative registry that names every registered
module, its owning slice, its registration date and a one-sentence
description, plus a check that the registry, the installed surface and the
files on disk all agree.

A registered module's name is its *importable* name -- ``cli`` for a flat
module, ``tools.shell`` for a package member.  The check is structural (it
never imports the module), so a name can never smuggle a path, a keyword or
an empty segment.

The registry is data, not code: it is a tuple of frozen records.  Mutating
one raises ``TypeError`` -- the records are immutable -- so the list cannot
drift at runtime.

This module never writes to ``pyproject.toml`` and never reads the wall
clock.  The registration date of a record is a field the caller supplies.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

COMPONENT = Path(__file__).resolve().parent
PYPROJECT = COMPONENT / "pyproject.toml"

#: Files that live in the component directory but are deliberately not
#: runtime modules.  ``tests/test_module_layout.py`` excludes the same two.
NON_RUNTIME_MODULES = frozenset({"setup.py", "conftest.py"})

#: A registration date is an ISO calendar date, e.g. ``"2026-11-14"``.
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _is_importable_module_name(name):
    """Is ``name`` the importable name of a runtime module?

    Two shapes are importable, and both are real in this component:

    * a **flat** module -- ``tools`` -- the file stem at the component root;
    * a **package member** -- ``tools.shell`` -- a module inside a package
      directory.

    A package member cannot appear in ``py-modules`` (that array lists flat
    names only); setuptools installs it through ``packages.find``.  Refusing
    a dotted name would therefore make the 22 installed package members
    *unregistrable* -- a gap in the registry's ability to name the runtime's
    modules at all, not merely a gap in its contents.

    The check is deliberately structural rather than "does it import": every
    dotted segment must be a valid Python identifier, so a name can never
    smuggle a path, a keyword, or an empty segment.
    """
    if not isinstance(name, str) or not name:
        return False
    return all(part.isidentifier() for part in name.split("."))


class RegistrationError(AssertionError):
    """Raised when the registry, ``pyproject.toml`` and the disk disagree.

    Subclasses ``AssertionError`` so a caller that only knows about
    assertions still catches it.
    """


class Registration:
    """One registered runtime module.

    ``module`` is the importable name: the file stem for a flat module
    (``cli``), the dotted name for a package member (``tools.shell``).
    ``slice_slug`` names the slice that introduced the module.
    ``registered_on`` is the ISO date the module entered the installed
    surface -- supplied by the caller, never read from the wall clock here.
    ``description`` is one sentence saying what the module is for.

    Instances are immutable: every attribute is read-only, and assigning to
    one raises ``AttributeError``.
    """

    __slots__ = ("module", "slice_slug", "registered_on", "description")

    def __init__(self, module, slice_slug, registered_on, description):
        missing = [
            name
            for name, value in (
                ("module", module),
                ("slice_slug", slice_slug),
                ("registered_on", registered_on),
                ("description", description),
            )
            if not isinstance(value, str) or not value.strip()
        ]
        if missing:
            raise ValueError(
                "registration for %r is missing required field(s): %s"
                % (module, ", ".join(missing))
            )
        if not _is_importable_module_name(module):
            raise ValueError(
                "module name %r is not an importable identifier" % (module,)
            )
        if not ISO_DATE.fullmatch(registered_on):
            raise ValueError(
                "registration date %r for %r is not an ISO date (YYYY-MM-DD)"
                % (registered_on, module)
            )
        object.__setattr__(self, "module", module)
        object.__setattr__(self, "slice_slug", slice_slug)
        object.__setattr__(self, "registered_on", registered_on)
        object.__setattr__(self, "description", description)

    def __setattr__(self, name, value):
        raise AttributeError(
            "Registration is immutable; cannot set %r on %r" % (name, self.module)
        )

    def __delattr__(self, name):
        raise AttributeError(
            "Registration is immutable; cannot delete %r on %r" % (name, self.module)
        )

    def __eq__(self, other):
        if not isinstance(other, Registration):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    def __hash__(self):
        return hash((self.module, self.slice_slug, self.registered_on, self.description))

    def __repr__(self):
        return "Registration(module=%r, slice_slug=%r, registered_on=%r)" % (
            self.module,
            self.slice_slug,
            self.registered_on,
        )

    def as_dict(self):
        """Return the record as a plain dict."""
        return {
            "module": self.module,
            "slice_slug": self.slice_slug,
            "registered_on": self.registered_on,
            "description": self.description,
        }


def _registration(module, slice_slug, registered_on, description):
    """Build one validated :class:`Registration`."""
    return Registration(module, slice_slug, registered_on, description)


#: Every runtime module of this component, sorted by module name.  The tuple
#: is the registry: it is read-only, and :func:`registered_modules` returns
#: it as-is rather than a copy, so a caller cannot mutate the registry
#: without going through the immutability of the records themselves.
REGISTRY = (
    _registration("_domain_base", "domain packs", "2026-10-06", "Shared base for the 39 domain packs."),
    _registration("_version", "dx foundations", "2026-09-07", "Single source of truth for the runtime version."),
    _registration("a2a_budget_combo", "runtime", "2026-10-07", "A2A delegation gated by the delegator's budget."),
    _registration("a2a_gates", "runtime", "2026-10-07", "A2A handoff gates: sabotage detection and turf-war detection."),
    _registration("a2abreak_probes", "probes", "2026-10-07", "A2ABreak-derived probe corpus for the governance bench."),
    _registration("ab_testing", "runtime", "2026-10-08", "A/B testing (experiment allocation) interface, simulated."),
    _registration("abac_engine", "runtime", "2026-10-08", "ABAC engine interface (XACML / OPA-Rego attribute policies, simulated)."),
    _registration("abe_interface", "runtime", "2026-10-07", "Attribute-based encryption (ABE) interface: policy-bound decryption."),
    _registration("abstract_interp", "runtime", "2026-10-07", "Abstract interpretation over the interval domain (Cousot & Cousot, 1977)."),
    _registration("abuse_limits", "runtime", "2026-10-08", "Abuse-prevention rate-limit rules: quotas, manual blocks, and appeals."),
    _registration("abuse_reporter", "runtime", "2026-10-08", "Abuse reporter: report / triage / resolve bookkeeping (simulated)."),
    _registration("account_recovery", "runtime", "2026-10-08", "Account recovery: code-issued recovery flows (simulated)."),
    _registration("action_card", "verifiable action cards (out-of-band approval ux) (eighty-fourth", "2026-10-04", "Verifiable action cards: approval UX the agent cannot forge."),
    _registration("action_verifier", "runtime", "2026-10-07", "Silent Stop action verification: narrating vs acting dissociate."),
    _registration("actionable_digest", "actionable-digest", "2026-11-14", "Actionable digest: stay silent unless the conjunctive fire condition holds."),
    _registration("active_learning", "runtime", "2026-10-08", "Active learning: query-acquisition governance ledger, Simulated."),
    _registration("activity_worker", "runtime", "2026-10-08", "Activity worker: Temporal-activities-shaped execution bookkeeping."),
    _registration("adjudication", "one-hundred-eighteenth", "2026-10-04", "Human final adjudication for AI sports systems (one-hundred-eighteenth batch)."),
    _registration("adtech_agents", "one-hundred-forty-ninth", "2026-10-04", "Adtech & synthetic-media disclosure discipline (one-hundred-forty-ninth batch)."),
    _registration("adversarial_detector", "runtime", "2026-10-07", "Adversarial example detector: statistical tripwires for perturbed inputs."),
    _registration("adversarial_robustness", "runtime", "2026-10-08", "Adversarial robustness (attack-test / harden / certify) interface, simulated."),
    _registration("agb_smoke_corpus", "bench", "2026-10-05", "AGB smoke corpus: AgentGuardBench-derived offline adversarial probes."),
    _registration("agent_files", "repository-defined agents and read-only agent skills for the gov", "2026-09-07", "Repository-defined subagents: ``.northstar/agents/*.md``."),
    _registration("agent_handoff", "agent-handoff", "2026-11-14", "Agent handoff: ``transfer_to_<name>`` tool with a fixed destination."),
    _registration("agent_identity", "eighty-fifth", "2026-10-04", "DID-based agent identity, delegation chains with depth limits, and permission-combination prohibition."),
    _registration("agent_memory", "runtime", "2026-10-08", "Key-addressed agent memory (store/recall/forget) interface, simulated."),
    _registration("agent_readiness", "one-hundred-first", "2026-10-04", "Agent-readiness probes for public-facing agent UI (one-hundred-first batch)."),
    _registration("agent_threat_bench_adapter", "harden agent runtime security and red-team governance", "2026-10-12", "Execution-aware adapter for AgentThreatBench samples."),
    _registration("agents", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Subagent definitions, the delegation rules around them, and acceptance semantics."),
    _registration("agri", "one-hundred-sixteenth", "2026-10-04", "Agriculture extension: scene-bound agri advice, field-condition envelopes, farmer data sovereignty, advice explainability, and smallholder access disclosure (one-hundred-sixteenth batch)."),
    _registration("agrifood_agents", "one-hundred-fifty-fourth", "2026-10-04", "Agriculture & food-system AI discipline (one-hundred-fifty-fourth batch)."),
    _registration("ai_accident", "runtime", "2026-10-08", "AI accident: accident report/investigation decision ledger, Simulated."),
    _registration("ai_accountability", "runtime", "2026-10-08", "AI accountability: accountability-assignment decision ledger, Simulated."),
    _registration("ai_accountability_auditing", "runtime", "2026-10-08", "AI accountability auditing: accountability-audit execution decision ledger, Simulated."),
    _registration("ai_accountability_certification", "runtime", "2026-10-08", "AI accountability certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_accountability_incident", "runtime", "2026-10-08", "AI accountability incident: accountability-incident report/investigate decision ledger, Simulated."),
    _registration("ai_accountability_mitigation", "runtime", "2026-10-08", "AI accountability mitigation: declared accountability-hazard mitigation decision ledger, Simulated."),
    _registration("ai_accountability_monitoring", "runtime", "2026-10-08", "AI accountability monitoring: accountability-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_accountability_remediation", "runtime", "2026-10-08", "AI accountability remediation: accountability-issue remediation decision ledger, Simulated."),
    _registration("ai_accountability_risk", "runtime", "2026-10-08", "AI accountability-risk register as a deterministic single-host decision ledger."),
    _registration("ai_accountability_testing", "runtime", "2026-10-08", "AI accountability testing: declared accountability-test-execution decision ledger, Simulated."),
    _registration("ai_accountability_threat", "runtime", "2026-10-08", "AI accountability threat: accountability-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_accountability_validation", "runtime", "2026-10-08", "AI accountability validation: accountability-validation decision ledger, Simulated."),
    _registration("ai_accountability_verification", "runtime", "2026-10-08", "AI accountability verification: declared accountability-check verification decision ledger, Simulated."),
    _registration("ai_accountability_vulnerability", "runtime", "2026-10-08", "AI accountability vulnerability: accountability-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_act", "runtime", "2026-10-08", "EU AI Act: risk-classification decision ledger, Simulated."),
    _registration("ai_adversarial", "runtime", "2026-10-08", "AI adversarial: adversarial test/defense decision ledger, Simulated."),
    _registration("ai_alignment", "runtime", "2026-10-08", "AI alignment assessment decision ledger, Simulated."),
    _registration("ai_assurance", "runtime", "2026-10-08", "AI assurance decision ledger: declare assurances, verify, derive posture."),
    _registration("ai_attack", "runtime", "2026-10-08", "AI attack: attack detection/defense decision ledger, Simulated."),
    _registration("ai_attestation", "runtime", "2026-10-08", "AI attestation (attest/verify/evaluate) interface, simulated."),
    _registration("ai_attribution", "runtime", "2026-10-08", "AI attribution (attribute/verify/evaluate) interface, simulated."),
    _registration("ai_audit", "runtime", "2026-10-08", "AI audit: audit-execution decision ledger, Simulated."),
    _registration("ai_benchmarking", "runtime", "2026-10-08", "AI benchmarking: AI-benchmarking decision ledger, Simulated."),
    _registration("ai_bias", "runtime", "2026-10-08", "AI bias: bias detection/mitigation decision ledger, Simulated."),
    _registration("ai_calibration", "runtime", "2026-10-08", "AI calibration: calibration-method declaration decision ledger, Simulated."),
    _registration("ai_certification", "runtime", "2026-10-08", "AI certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_charter", "runtime", "2026-10-08", "AI charter: charter-commitment decision ledger, Simulated."),
    _registration("ai_circuit", "runtime", "2026-10-08", "AI circuit (analyze/verify/evaluate) interface, simulated."),
    _registration("ai_compliance", "runtime", "2026-10-08", "AI compliance: AI-compliance-assessment decision ledger, Simulated."),
    _registration("ai_compliance_auditing", "runtime", "2026-10-08", "AI compliance auditing: compliance-audit execution decision ledger, Simulated."),
    _registration("ai_compliance_certification", "runtime", "2026-10-08", "AI compliance certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_compliance_incident", "runtime", "2026-10-08", "AI compliance incident: compliance-incident report/investigate decision ledger, Simulated."),
    _registration("ai_compliance_mitigation", "runtime", "2026-10-08", "AI compliance mitigation: declared compliance-hazard mitigation decision ledger, Simulated."),
    _registration("ai_compliance_monitoring", "runtime", "2026-10-08", "AI compliance monitoring: compliance-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_compliance_remediation", "runtime", "2026-10-08", "AI compliance remediation: compliance-issue remediation decision ledger, Simulated."),
    _registration("ai_compliance_risk", "runtime", "2026-10-08", "AI compliance-risk register as a deterministic single-host decision ledger."),
    _registration("ai_compliance_testing", "runtime", "2026-10-08", "AI compliance testing: declared compliance-test-execution decision ledger, Simulated."),
    _registration("ai_compliance_threat", "runtime", "2026-10-08", "AI compliance threat: compliance-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_compliance_validation", "runtime", "2026-10-08", "AI compliance validation: compliance-validation decision ledger, Simulated."),
    _registration("ai_compliance_verification", "runtime", "2026-10-08", "AI compliance verification: declared compliance-check verification decision ledger, Simulated."),
    _registration("ai_compliance_vulnerability", "runtime", "2026-10-08", "AI compliance vulnerability: compliance-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_concept", "runtime", "2026-10-08", "AI concept extraction: concept inventory decision ledger, Simulated."),
    _registration("ai_constitution", "runtime", "2026-10-08", "AI constitution (declare/verify/evaluate) interface, simulated."),
    _registration("ai_containment", "runtime", "2026-10-08", "AI containment: containment declare/verify decision ledger, Simulated."),
    _registration("ai_contestability_auditing", "runtime", "2026-10-08", "AI contestability auditing: contestability-audit execution decision ledger, Simulated."),
    _registration("ai_contestability_certification", "runtime", "2026-10-08", "AI contestability certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_contestability_incident", "runtime", "2026-10-08", "AI contestability incident: contestability-incident report/investigate decision ledger, Simulated."),
    _registration("ai_contestability_mitigation", "runtime", "2026-10-08", "AI contestability mitigation: declared contestability-hazard mitigation decision ledger, Simulated."),
    _registration("ai_contestability_monitoring", "runtime", "2026-10-08", "AI contestability monitoring: contestability-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_contestability_remediation", "runtime", "2026-10-08", "AI contestability remediation: contestability-issue remediation decision ledger, Simulated."),
    _registration("ai_contestability_risk", "runtime", "2026-10-08", "AI contestability-risk register as a deterministic single-host decision ledger."),
    _registration("ai_contestability_testing", "runtime", "2026-10-08", "AI contestability testing: declared contestability-test-execution decision ledger, Simulated."),
    _registration("ai_contestability_threat", "runtime", "2026-10-08", "AI contestability threat: contestability-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_contestability_validation", "runtime", "2026-10-08", "AI contestability validation: contestability-validation decision ledger, Simulated."),
    _registration("ai_contestability_verification", "runtime", "2026-10-08", "AI contestability verification: declared contestability-check verification decision ledger, Simulated."),
    _registration("ai_contestability_vulnerability", "runtime", "2026-10-08", "AI contestability vulnerability: contestability-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_counterfactual", "runtime", "2026-10-08", "AI counterfactual: declared what-if decision ledger, Simulated."),
    _registration("ai_defense", "runtime", "2026-10-08", "AI defense: defense-operations decision ledger, Simulated."),
    _registration("ai_detection", "runtime", "2026-10-08", "AI detection: AI-generated-content detection decision ledger, Simulated."),
    _registration("ai_distillation", "runtime", "2026-10-08", "AI distillation: knowledge-distillation declaration decision ledger, Simulated."),
    _registration("ai_distribution_shift", "runtime", "2026-10-08", "AI distribution shift: detection decision ledger, Simulated."),
    _registration("ai_ensemble", "runtime", "2026-10-08", "AI ensemble: ensemble-composition decision ledger, Simulated."),
    _registration("ai_ethics", "runtime", "2026-10-08", "AI ethics assessment (assess/verify/evaluate) interface, simulated."),
    _registration("ai_ethics_auditing", "runtime", "2026-10-08", "AI ethics auditing: ethics-audit execution decision ledger, Simulated."),
    _registration("ai_ethics_certification", "runtime", "2026-10-08", "AI ethics certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_ethics_incident", "runtime", "2026-10-08", "AI ethics incident: ethics-incident report/investigate decision ledger, Simulated."),
    _registration("ai_ethics_mitigation", "runtime", "2026-10-08", "AI ethics mitigation: declared ethics-hazard mitigation decision ledger, Simulated."),
    _registration("ai_ethics_monitoring", "runtime", "2026-10-08", "AI ethics monitoring: ethics-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_ethics_remediation", "runtime", "2026-10-08", "AI ethics remediation: ethics-issue remediation decision ledger, Simulated."),
    _registration("ai_ethics_risk", "runtime", "2026-10-08", "AI ethics-risk register as a deterministic single-host decision ledger."),
    _registration("ai_ethics_testing", "runtime", "2026-10-08", "AI ethics testing: declared ethics-test-execution decision ledger, Simulated."),
    _registration("ai_ethics_threat", "runtime", "2026-10-08", "AI ethics threat: ethics-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_ethics_validation", "runtime", "2026-10-08", "AI ethics validation: ethics-validation decision ledger, Simulated."),
    _registration("ai_ethics_verification", "runtime", "2026-10-08", "AI ethics verification: ethics-check verification decision ledger, Simulated."),
    _registration("ai_ethics_vulnerability", "runtime", "2026-10-08", "AI ethics vulnerability: ethics-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_evaluation", "runtime", "2026-10-08", "AI evaluation: declared-evaluation decision ledger, Simulated."),
    _registration("ai_explainability", "runtime", "2026-10-08", "AI explainability provision decision ledger, Simulated."),
    _registration("ai_exploit", "runtime", "2026-10-08", "AI exploit: declared exploit detection/mitigation decision ledger, Simulated."),
    _registration("ai_failure", "runtime", "2026-10-08", "AI failure: failure report/analysis decision ledger, Simulated."),
    _registration("ai_fairness", "runtime", "2026-10-08", "AI fairness assessment/mitigation (assess/mitigate/verify), simulated."),
    _registration("ai_fairness_auditing", "runtime", "2026-10-08", "AI fairness auditing: fairness-audit execution decision ledger, Simulated."),
    _registration("ai_fairness_certification", "runtime", "2026-10-08", "AI fairness certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_fairness_incident", "runtime", "2026-10-08", "AI fairness incident: fairness-incident report/investigate decision ledger, Simulated."),
    _registration("ai_fairness_mitigation", "runtime", "2026-10-08", "AI fairness mitigation: declared fairness-hazard mitigation decision ledger, Simulated."),
    _registration("ai_fairness_monitoring", "runtime", "2026-10-08", "AI fairness monitoring: fairness-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_fairness_remediation", "runtime", "2026-10-08", "AI fairness remediation: fairness-issue remediation decision ledger, Simulated."),
    _registration("ai_fairness_risk", "runtime", "2026-10-08", "AI fairness-risk register as a deterministic single-host decision ledger."),
    _registration("ai_fairness_testing", "runtime", "2026-10-08", "AI fairness testing: declared fairness-test-execution decision ledger, Simulated."),
    _registration("ai_fairness_threat", "runtime", "2026-10-08", "AI fairness threat: fairness-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_fairness_validation", "runtime", "2026-10-08", "AI fairness validation: fairness-validation decision ledger, Simulated."),
    _registration("ai_fairness_verification", "runtime", "2026-10-08", "AI fairness verification: fairness-check verification decision ledger, Simulated."),
    _registration("ai_fairness_vulnerability", "runtime", "2026-10-08", "AI fairness vulnerability: fairness-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_feature", "runtime", "2026-10-08", "AI feature: AI-feature-extraction decision ledger, Simulated."),
    _registration("ai_fuzzing", "runtime", "2026-10-08", "AI fuzzing: fuzz-campaign decision ledger, Simulated."),
    _registration("ai_gating", "runtime", "2026-10-08", "AI gating: capability-gating decision ledger, Simulated."),
    _registration("ai_governance", "runtime", "2026-10-08", "AI governance operations decision ledger: declare controls, book audits."),
    _registration("ai_harm", "runtime", "2026-10-08", "AI harm: harm assessment/mitigation decision ledger, Simulated."),
    _registration("ai_incident", "runtime", "2026-10-08", "AI incident: incident report/investigate decision ledger, Simulated."),
    _registration("ai_interpretability", "runtime", "2026-10-08", "AI interpretability (system-level assessment) interface, simulated."),
    _registration("ai_isolation", "runtime", "2026-10-08", "AI isolation: isolation -> verify decision ledger, Simulated."),
    _registration("ai_liability", "runtime", "2026-10-08", "AI liability decision ledger: declare liability assessments, book assignments."),
    _registration("ai_mechanistic", "runtime", "2026-10-08", "AI mechanistic analysis decision ledger, Simulated."),
    _registration("ai_mitigation", "runtime", "2026-10-08", "AI mitigation: declared risk-mitigation decision ledger, Simulated."),
    _registration("ai_monitoring", "runtime", "2026-10-08", "AI monitoring: monitor/alert decision ledger, Simulated."),
    _registration("ai_ood_detection", "runtime", "2026-10-08", "AI OOD detection: out-of-distribution detection decision ledger, Simulated."),
    _registration("ai_oversight", "runtime", "2026-10-08", "AI oversight decision ledger: declare oversight sessions, book verdicts."),
    _registration("ai_oversight_auditing", "runtime", "2026-10-08", "AI oversight auditing: oversight-audit execution decision ledger, Simulated."),
    _registration("ai_oversight_certification", "runtime", "2026-10-08", "AI oversight certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_oversight_incident", "runtime", "2026-10-08", "AI oversight incident: oversight-incident report/investigate decision ledger, Simulated."),
    _registration("ai_oversight_mitigation", "runtime", "2026-10-08", "AI oversight mitigation: declared oversight-hazard mitigation decision ledger, Simulated."),
    _registration("ai_oversight_monitoring", "runtime", "2026-10-08", "AI oversight monitoring: oversight-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_oversight_remediation", "runtime", "2026-10-08", "AI oversight remediation: oversight-issue remediation decision ledger, Simulated."),
    _registration("ai_oversight_risk", "runtime", "2026-10-08", "AI oversight-risk register as a deterministic single-host decision ledger."),
    _registration("ai_oversight_testing", "runtime", "2026-10-08", "AI oversight testing: declared oversight-test-execution decision ledger, Simulated."),
    _registration("ai_oversight_threat", "runtime", "2026-10-08", "AI oversight threat: oversight-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_oversight_validation", "runtime", "2026-10-08", "AI oversight validation: oversight-validation decision ledger, Simulated."),
    _registration("ai_oversight_verification", "runtime", "2026-10-08", "AI oversight verification: declared oversight-check verification decision ledger, Simulated."),
    _registration("ai_oversight_vulnerability", "runtime", "2026-10-08", "AI oversight vulnerability: oversight-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_pentesting", "runtime", "2026-10-08", "AI pentesting: penetration-test decision ledger, Simulated."),
    _registration("ai_perturbation", "runtime", "2026-10-08", "AI perturbation (perturb/verify/evaluate) interface, simulated."),
    _registration("ai_policy", "runtime", "2026-10-08", "AI policy declaration/enforcement decision ledger: declare policies, book enforcements."),
    _registration("ai_prevention", "runtime", "2026-10-08", "AI prevention: prevention-control decision ledger, Simulated."),
    _registration("ai_principles", "runtime", "2026-10-08", "AI principles declaration (declare/verify/evaluate) interface, simulated."),
    _registration("ai_privacy", "runtime", "2026-10-08", "AI privacy: privacy assessment/protection decision ledger, Simulated."),
    _registration("ai_probing", "runtime", "2026-10-08", "AI probing: model-probing decision ledger, Simulated."),
    _registration("ai_pruning", "runtime", "2026-10-08", "AI pruning: declared pruning-operation decision ledger, Simulated."),
    _registration("ai_quarantine", "runtime", "2026-10-08", "AI quarantine: quarantine/verify decision ledger, Simulated."),
    _registration("ai_recourse", "runtime", "2026-10-08", "AI recourse decision ledger: declare recourse, verify, derive posture."),
    _registration("ai_recovery", "runtime", "2026-10-08", "AI recovery: incident-recovery decision ledger, Simulated."),
    _registration("ai_redress", "runtime", "2026-10-08", "AI redress: remedy-provision decision ledger, Simulated."),
    _registration("ai_redteaming", "runtime", "2026-10-08", "AI red-teaming: red-team exercise decision ledger, Simulated."),
    _registration("ai_regulation", "runtime", "2026-10-08", "AI regulation compliance decision ledger: declare assessments, book enforcement."),
    _registration("ai_remediation", "runtime", "2026-10-08", "AI remediation: remediation-action decision ledger, Simulated."),
    _registration("ai_resilience", "runtime", "2026-10-08", "AI resilience: resilience assessment -> strengthening decision ledger, Simulated."),
    _registration("ai_risk", "runtime", "2026-10-08", "AI-risk assessment/mitigation decision ledger as a deterministic single-host state machine."),
    _registration("ai_robustness", "runtime", "2026-10-08", "AI robustness: robustness test-governance decision ledger, Simulated."),
    _registration("ai_robustness_auditing", "batch-78", "2026-10-08", "AI robustness auditing: robustness-audit execution decision ledger, Simulated."),
    _registration("ai_robustness_certification", "batch-78", "2026-10-08", "AI robustness certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_robustness_incident", "batch-78", "2026-10-08", "AI robustness incident: robustness-incident report/investigate decision ledger, Simulated."),
    _registration("ai_robustness_mitigation", "batch-78", "2026-10-08", "AI robustness mitigation: declared robustness-hazard mitigation decision ledger, Simulated."),
    _registration("ai_robustness_monitoring", "batch-78", "2026-10-08", "AI robustness monitoring: robustness-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_robustness_remediation", "batch-78", "2026-10-08", "AI robustness remediation: robustness-issue remediation decision ledger, Simulated."),
    _registration("ai_robustness_risk", "batch-78", "2026-10-08", "AI robustness-risk register as a deterministic single-host decision ledger."),
    _registration("ai_robustness_testing", "runtime", "2026-10-08", "AI robustness testing: test-execution-run decision ledger, Simulated."),
    _registration("ai_robustness_threat", "batch-78", "2026-10-08", "AI robustness threat: robustness-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_robustness_validation", "batch-78", "2026-10-08", "AI robustness validation: robustness-validation decision ledger, Simulated."),
    _registration("ai_robustness_verification", "batch-78", "2026-10-08", "AI robustness verification: declared robustness-check verification decision ledger, Simulated."),
    _registration("ai_robustness_vulnerability", "batch-78", "2026-10-08", "AI robustness vulnerability: robustness-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_safety", "runtime", "2026-10-08", "AI safety: safety assessment/mitigation decision ledger, Simulated."),
    _registration("ai_safety_auditing", "runtime", "2026-10-08", "AI safety auditing: safety-audit execution decision ledger, Simulated."),
    _registration("ai_safety_certification", "runtime", "2026-10-08", "AI safety certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_safety_incident", "runtime", "2026-10-08", "AI safety incident: safety-incident report/investigate decision ledger, Simulated."),
    _registration("ai_safety_mitigation", "runtime", "2026-10-08", "AI safety mitigation: declared safety-hazard mitigation decision ledger, Simulated."),
    _registration("ai_safety_monitoring", "runtime", "2026-10-08", "AI safety monitoring: safety-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_safety_remediation", "runtime", "2026-10-08", "AI safety remediation: safety-hazard remediation decision ledger, Simulated."),
    _registration("ai_safety_risk", "runtime", "2026-10-08", "AI safety-risk register as a deterministic single-host decision ledger."),
    _registration("ai_safety_testing", "runtime", "2026-10-08", "AI safety testing: declared safety-test-execution decision ledger, Simulated."),
    _registration("ai_safety_threat", "runtime", "2026-10-08", "AI safety threat: safety-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_safety_validation", "runtime", "2026-10-08", "AI safety validation: safety-validation decision ledger, Simulated."),
    _registration("ai_safety_verification", "runtime", "2026-10-08", "AI safety verification: safety-check verification decision ledger, Simulated."),
    _registration("ai_safety_vulnerability", "runtime", "2026-10-08", "AI safety vulnerability: safety-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_saliency", "runtime", "2026-10-08", "AI saliency: saliency-map computation decision ledger, Simulated."),
    _registration("ai_sandbox", "runtime", "2026-10-08", "AI sandbox: declared sandbox-execution decision ledger, Simulated."),
    _registration("ai_security", "runtime", "2026-10-08", "AI security: security assessment/mitigation decision ledger, Simulated."),
    _registration("ai_standards", "runtime", "2026-10-08", "AI standards conformance (declare/verify/evaluate) interface, simulated."),
    _registration("ai_stress_testing", "runtime", "2026-10-08", "AI stress testing: declared stress-regime decision ledger, Simulated."),
    _registration("ai_surveillance", "runtime", "2026-10-08", "AI surveillance: watch-observation decision ledger, Simulated."),
    _registration("ai_testing", "runtime", "2026-10-08", "AI testing: declared test-execution decision ledger, Simulated."),
    _registration("ai_threat", "runtime", "2026-10-08", "AI threat: AI-capability threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_throttling", "runtime", "2026-10-08", "AI throttling: throttling-operations decision ledger, Simulated."),
    _registration("ai_traceability_auditing", "batch-77", "2026-10-08", "AI traceability auditing: traceability-audit execution decision ledger, Simulated."),
    _registration("ai_traceability_certification", "batch-77", "2026-10-08", "AI traceability certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_traceability_incident", "batch-77", "2026-10-08", "AI traceability incident: traceability-incident report/investigate decision ledger, Simulated."),
    _registration("ai_traceability_mitigation", "batch-77", "2026-10-08", "AI traceability mitigation: declared traceability-hazard mitigation decision ledger, Simulated."),
    _registration("ai_traceability_monitoring", "batch-77", "2026-10-08", "AI traceability monitoring: traceability-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_traceability_remediation", "batch-77", "2026-10-08", "AI traceability remediation: traceability-issue remediation decision ledger, Simulated."),
    _registration("ai_traceability_risk", "batch-77", "2026-10-08", "AI traceability-risk register as a deterministic single-host decision ledger."),
    _registration("ai_traceability_testing", "batch-77", "2026-10-08", "AI traceability testing: declared traceability-test-execution decision ledger, Simulated."),
    _registration("ai_traceability_threat", "batch-77", "2026-10-08", "AI traceability threat: traceability-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_traceability_validation", "batch-77", "2026-10-08", "AI traceability validation: traceability-validation decision ledger, Simulated."),
    _registration("ai_traceability_verification", "batch-77", "2026-10-08", "AI traceability verification: declared traceability-check verification decision ledger, Simulated."),
    _registration("ai_traceability_vulnerability", "batch-77", "2026-10-08", "AI traceability vulnerability: traceability-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_transparency", "runtime", "2026-10-08", "AI transparency: transparency disclosure decision ledger, Simulated."),
    _registration("ai_transparency_auditing", "runtime", "2026-10-08", "AI transparency auditing: transparency-audit execution decision ledger, Simulated."),
    _registration("ai_transparency_certification", "runtime", "2026-10-08", "AI transparency certification (certify/verify/evaluate) interface, simulated."),
    _registration("ai_transparency_incident", "runtime", "2026-10-08", "AI transparency incident: transparency-incident report/investigate decision ledger, Simulated."),
    _registration("ai_transparency_mitigation", "runtime", "2026-10-08", "AI transparency mitigation: declared transparency-hazard mitigation decision ledger, Simulated."),
    _registration("ai_transparency_monitoring", "runtime", "2026-10-08", "AI transparency monitoring: transparency-signal monitor/alert decision ledger, Simulated."),
    _registration("ai_transparency_remediation", "runtime", "2026-10-08", "AI transparency remediation: transparency-issue remediation decision ledger, Simulated."),
    _registration("ai_transparency_risk", "runtime", "2026-10-08", "AI transparency-risk register as a deterministic single-host decision ledger."),
    _registration("ai_transparency_testing", "runtime", "2026-10-08", "AI transparency testing: declared transparency-test-execution decision ledger, Simulated."),
    _registration("ai_transparency_threat", "runtime", "2026-10-08", "AI transparency threat: transparency-threat assessment/mitigation decision ledger, Simulated."),
    _registration("ai_transparency_validation", "runtime", "2026-10-08", "AI transparency validation: transparency-validation decision ledger, Simulated."),
    _registration("ai_transparency_verification", "runtime", "2026-10-08", "AI transparency verification: transparency-check verification decision ledger, Simulated."),
    _registration("ai_transparency_vulnerability", "runtime", "2026-10-08", "AI transparency vulnerability: transparency-weakness detection/mitigation decision ledger, Simulated."),
    _registration("ai_uncertainty", "runtime", "2026-10-08", "AI uncertainty: uncertainty-quantification decision ledger, Simulated."),
    _registration("ai_validation", "runtime", "2026-10-08", "AI validation: validation decision ledger, Simulated."),
    _registration("ai_verification", "runtime", "2026-10-08", "AI verification: verify/certify decision ledger, Simulated."),
    _registration("ai_visualization", "runtime", "2026-10-08", "AI visualization: interpretability-visualization decision ledger, Simulated."),
    _registration("ai_vulnerability", "runtime", "2026-10-08", "AI vulnerability: vulnerability detection/mitigation decision ledger, Simulated."),
    _registration("akf_export", "audit export --akf", "2026-10-04", "Export a Northstar audit feed as an AKF v1.1 unit (spike)."),
    _registration("alert_manager", "runtime", "2026-10-07", "Alert manager interface (Prometheus Alertmanager-style routing, simulated)."),
    _registration("alert_trigger_registry", "b173 slice4 (part 1): alert trigger registry + audit-sink reader", "2026-11-11", "Concrete audit-sink alert trigger registry."),
    _registration("alerting_rules", "runtime", "2026-10-08", "Alerting rules — simulated Alertmanager/PagerDuty bookkeeping (thirty-fourth batch)."),
    _registration("aligned_ai", "runtime", "2026-10-08", "AlignedAI: alignment-assessment decision ledger, Simulated."),
    _registration("alignment_check", "alignment-check", "2026-10-08", "Alignment check: goal-trace-action observer (LlamaFirewall), Simulated."),
    _registration("alignment_eval", "runtime", "2026-10-08", "AlignmentEval: declared alignment-testing scenario/judge/grade bookkeeping."),
    _registration("allowlist", "allowlist", "2026-10-09", "Allowlist validation (D-IN-027), Simulated."),
    _registration("aml_screener", "runtime", "2026-10-08", "aml_screener.py — sanctions / watchlist screening bookkeeping."),
    _registration("amplification", "runtime", "2026-10-08", "Amplification / distillation decision ledger, Simulated."),
    _registration("amqp_broker", "runtime", "2026-10-08", "AMQPBroker: RabbitMQ-shaped exchange/queue/bind message routing."),
    _registration("analytics_tracker", "runtime", "2026-10-08", "Event analytics tracker (twenty-ninth batch)."),
    _registration("annotation_pin", "outsideloop", "2026-11-14", "Annotation-hint pinning for MCP tools (silent-widening defense), Simulated."),
    _registration("ansible_playbook", "runtime", "2026-10-07", "Ansible playbook interface: config management as a deterministic state machine."),
    _registration("anti_entropy", "runtime", "2026-10-08", "Anti-entropy via Merkle-tree sync (Dynamo/Riak shaped)."),
    _registration("api_analytics", "runtime", "2026-10-08", "API analytics (thirty-fourth batch)."),
    _registration("api_client_gen", "runtime", "2026-10-08", "API client generator interface (OpenAPI codegen shaped, simulated)."),
    _registration("api_gateway", "runtime", "2026-10-07", "API gateway interface: route matching, plugin chaining, request transforms, and throttle policies for agent traffic."),
    _registration("api_versioning", "runtime", "2026-10-08", "API versioning — Stripe-shaped API version lifecycle bookkeeping."),
    _registration("apikey_manager", "runtime", "2026-10-08", "API key manager: issuance, rotation, revocation, and verification (simulated)."),
    _registration("approval_chain", "runtime", "2026-10-07", "Approval chain: SLA queue -> signed receipt -> edge gate, wired end to end."),
    _registration("approval_chain_time", "runtime", "2026-10-07", "Approval chain with wall-clock SLA: SLA queue -> signed receipt -> edge gate."),
    _registration("approval_fatigue_probes", "runtime", "2026-10-07", "Approval-fatigue probe corpus (consent-fatigue HITL bypass)."),
    _registration("approval_rules", "msaf-lineage", "2026-11-13", "Standing approval rules: approval as data, not a callback."),
    _registration("approval_sla", "runtime", "2026-10-07", "SLA-bound approval queue for abstain-to-human escalation."),
    _registration("approval_sla_time", "runtime", "2026-10-07", "SLA-bound approval queue, wall-clock variant."),
    _registration("approver_separation", "ninety-fourth", "2026-10-04", "No-self-attestation: the proposer is never its own approver."),
    _registration("argument_smuggling_probes", "runtime", "2026-10-07", "Argument-smuggling probes: smuggling shapes, schema bypass, downstream meaning."),
    _registration("artifact_authority", "vina", "2026-11-14", "Artifact authority: the artifact carries the authority it was granted."),
    _registration("artifact_graph_probes", "runtime", "2026-10-07", "Artifact-graph probes: lineage forgery / graph diagnosis / artifact integrity."),
    _registration("artifact_publisher", "runtime", "2026-10-08", "Artifact publisher: PyPI-style build/upload/yank bookkeeping (simulated)."),
    _registration("asi02_probe", "asi02-probe", "2026-10-08", "ASI02 probe harness: OWASP 8 primitives (attack), Simulated."),
    _registration("asi04_probes", "governance", "2026-10-06", "ASI04 probe corpus: skill-mediated attack probes."),
    _registration("asi07_corpus", "bench", "2026-10-06", "ASI07 probe corpus: multi-agent attack templates for the governance bench."),
    _registration("asi08_probes", "governance", "2026-10-06", "ASI08 probe corpus: cascading failure / blast-radius probes."),
    _registration("asi09_probes", "governance", "2026-10-06", "ASI09 probe corpus: human-agent trust calibration probes."),
    _registration("ask_or_solve_probes", "runtime", "2026-10-07", "Ask-or-solve probes: first-class questioning under uncertainty."),
    _registration("assistance_game", "runtime", "2026-10-08", "Assistance-game (cooperative assistance) decision ledger, Simulated."),
    _registration("assurance", "runtime", "2026-10-08", "Assurance-case (argue/verify/maintain) interface, simulated."),
    _registration("attack_extra_01", "worker", "2026-10-09", "Prompt-leak via completion (attack_extra_01), Simulated."),
    _registration("attack_extra_02", "worker", "2026-10-09", "Instruction hierarchy confusion (attack_extra_02), Simulated."),
    _registration("attack_extra_03", "worker", "2026-10-09", "Tool-output fake system messages (attack_extra_03), Simulated."),
    _registration("attack_extra_04", "worker", "2026-10-09", "Multi-agent collusion (attack_extra_04), Simulated."),
    _registration("attack_extra_05", "worker", "2026-10-09", "Delegation chain attacks (attack_extra_05), Simulated."),
    _registration("attack_extra_06", "worker", "2026-10-09", "Time-of-check / time-of-use in gates (attack_extra_06), Simulated."),
    _registration("attack_extra_07", "worker", "2026-10-09", "Race conditions in approval (attack_extra_07), Simulated."),
    _registration("attack_extra_08", "worker", "2026-10-09", "Cache poisoning for tools (attack_extra_08), Simulated."),
    _registration("attack_extra_09", "worker", "2026-10-09", "DNS rebinding for tool endpoints (attack_extra_09), Simulated."),
    _registration("attack_extra_10", "worker", "2026-10-09", "Subdomain takeover for webhooks (attack_extra_10), Simulated."),
    _registration("attack_extra_11", "worker", "2026-10-09", "JWT confusion attacks (attack_extra_11), Simulated."),
    _registration("attack_extra_12", "worker", "2026-10-09", "OAuth scope escalation (attack_extra_12), Simulated."),
    _registration("attack_extra_13", "worker", "2026-10-09", "API key leakage via error messages (attack_extra_13), Simulated."),
    _registration("attack_extra_14", "worker", "2026-10-09", "Verbose error exfiltration (attack_extra_14), Simulated."),
    _registration("attack_extra_15", "worker", "2026-10-09", "Debug endpoint exposure (attack_extra_15), Simulated."),
    _registration("attack_extra_16", "worker", "2026-10-09", "Health check info leakage (attack_extra_16), Simulated."),
    _registration("attack_extra_17", "worker", "2026-10-09", "Metrics endpoint exfiltration (attack_extra_17), Simulated."),
    _registration("attack_extra_18", "worker", "2026-10-09", "Pprof exposure (attack_extra_18), Simulated."),
    _registration("attack_extra_19", "worker", "2026-10-09", "GraphQL introspection abuse (attack_extra_19), Simulated."),
    _registration("attack_extra_20", "worker", "2026-10-09", "WebSocket hijacking (attack_extra_20), Simulated."),
    _registration("attested_receipts", "ninety-second", "2026-10-04", "TEE attestation as receipt evidence (ninety-second batch)."),
    _registration("attribution", "runtime", "2026-10-08", "attribution.py — source-attribution bookkeeping for content provenance."),
    _registration("audio_processor", "runtime", "2026-10-08", "Audio format conversion, loudness normalization, and trimming."),
    _registration("audit_agents", "one-hundred-forty-third", "2026-10-04", "Audit & assurance discipline (one-hundred-forty-third batch)."),
    _registration("audit_archive", "audit", "2026-10-03", "WORM-ready archive packages for audit feeds (``northstar-audit-archive/1``)."),
    _registration("audit_chain", "audit", "2026-10-03", "Tamper-evident hash chain for the ``audit.ndjson/1`` feed."),
    _registration("audit_cli", "audit", "2026-10-03", "The ``audit`` command: verify (and anchor) tamper-evident audit feeds."),
    _registration("audit_committee", "runtime", "2026-10-08", "AuditCommittee: independent audit-committee governance bookkeeping."),
    _registration("audit_compaction", "runtime", "2026-10-07", "Log-structured merge compaction for audit feeds."),
    _registration("audit_export", "P3-1a", "2026-09-07", "Export session transcripts as the canonical NDJSON audit feed (audit v1)."),
    _registration("audit_head_holder", "audit-head", "2026-11-12", "Independent audit-head holder: a second copy of the sealed head."),
    _registration("audit_management", "runtime", "2026-10-08", "Audit-engagement management decision ledger: plan, execute, followup."),
    _registration("audit_merkle", "rfc 9162 merkle proofs for audit (seventy-ninth batch)", "2026-10-04", "RFC 9162 Merkle proofs for the ``audit.ndjson/1`` chained feed."),
    _registration("audit_rekor", "audit", "2026-10-03", "External head anchoring for audit feeds via the Sigstore Rekor transparency log."),
    _registration("audit_scitt", "scitt (rfc 9943) / cose receipt spike for the audit chain (seven", "2026-10-04", "SCITT (RFC 9943) / COSE Receipts (RFC 9942) export spike for audit feeds."),
    _registration("audit_shipper", "runtime", "2026-10-08", "Audit log shipper: batch audit records and forward them to a SIEM sink."),
    _registration("auth_dict", "runtime", "2026-10-07", "Authenticated dictionary: a key/value map with Merkle inclusion proofs."),
    _registration("automated_alignment", "runtime", "2026-10-08", "Automated alignment as a deterministic single-host decision ledger."),
    _registration("b64_detect", "b64-detect", "2026-10-09", "Base64 detection (D-IN-009), Simulated."),
    _registration("ba_01", "ba", "2026-10-09", "ba_01: add_two utility."),
    _registration("ba_02", "ba", "2026-10-09", "ba_02: square utility."),
    _registration("ba_03", "ba", "2026-10-09", "ba_03: cube utility."),
    _registration("ba_04", "ba", "2026-10-09", "ba_04: neg utility."),
    _registration("ba_05", "ba", "2026-10-09", "ba_05: double utility."),
    _registration("ba_06", "ba", "2026-10-09", "ba_06: half utility."),
    _registration("ba_07", "ba", "2026-10-09", "ba_07: inc utility."),
    _registration("ba_08", "ba", "2026-10-09", "ba_08: dec utility."),
    _registration("ba_09", "ba", "2026-10-09", "ba_09: absv utility."),
    _registration("ba_10", "ba", "2026-10-09", "ba_10: is_even utility."),
    _registration("ba_11", "ba", "2026-10-09", "ba_11: is_odd utility."),
    _registration("ba_12", "ba", "2026-10-09", "ba_12: is_pos utility."),
    _registration("ba_13", "ba", "2026-10-09", "ba_13: is_neg utility."),
    _registration("ba_14", "ba", "2026-10-09", "ba_14: is_zero utility."),
    _registration("ba_15", "ba", "2026-10-09", "ba_15: sign utility."),
    _registration("ba_16", "ba", "2026-10-09", "ba_16: clamp01 utility."),
    _registration("ba_17", "ba", "2026-10-09", "ba_17: pct utility."),
    _registration("ba_18", "ba", "2026-10-09", "ba_18: per_mille utility."),
    _registration("ba_19", "ba", "2026-10-09", "ba_19: ceil2 utility."),
    _registration("ba_20", "ba", "2026-10-09", "ba_20: floor2 utility."),
    _registration("ba_21", "ba", "2026-10-09", "ba_21: mod10 utility."),
    _registration("ba_22", "ba", "2026-10-09", "ba_22: div10 utility."),
    _registration("ba_23", "ba", "2026-10-09", "ba_23: last_digit utility."),
    _registration("ba_24", "ba", "2026-10-09", "ba_24: first_digit utility."),
    _registration("ba_25", "ba", "2026-10-09", "ba_25: digits utility."),
    _registration("ba_26", "ba", "2026-10-09", "ba_26: digit_sum utility."),
    _registration("ba_27", "ba", "2026-10-09", "ba_27: reverse_int utility."),
    _registration("ba_28", "ba", "2026-10-09", "ba_28: is_pal utility."),
    _registration("ba_29", "ba", "2026-10-09", "ba_29: upper utility."),
    _registration("ba_30", "ba", "2026-10-09", "ba_30: lower utility."),
    _registration("ba_31", "ba", "2026-10-09", "ba_31: strip utility."),
    _registration("ba_32", "ba", "2026-10-09", "ba_32: title utility."),
    _registration("ba_33", "ba", "2026-10-09", "ba_33: swapcase utility."),
    _registration("ba_34", "ba", "2026-10-09", "ba_34: reverse_str utility."),
    _registration("ba_35", "ba", "2026-10-09", "ba_35: length utility."),
    _registration("ba_36", "ba", "2026-10-09", "ba_36: char0 utility."),
    _registration("ba_37", "ba", "2026-10-09", "ba_37: char_last utility."),
    _registration("ba_38", "ba", "2026-10-09", "ba_38: no_space utility."),
    _registration("ba_39", "ba", "2026-10-09", "ba_39: words utility."),
    _registration("ba_40", "ba", "2026-10-09", "ba_40: slug utility."),
    _registration("ba_41", "ba", "2026-10-09", "ba_41: camel utility."),
    _registration("ba_42", "ba", "2026-10-09", "ba_42: snake utility."),
    _registration("ba_43", "ba", "2026-10-09", "ba_43: repeat utility."),
    _registration("ba_44", "ba", "2026-10-09", "ba_44: exclaim utility."),
    _registration("ba_45", "ba", "2026-10-09", "ba_45: question utility."),
    _registration("ba_46", "ba", "2026-10-09", "ba_46: quote utility."),
    _registration("ba_47", "ba", "2026-10-09", "ba_47: paren utility."),
    _registration("ba_48", "ba", "2026-10-09", "ba_48: bracket utility."),
    _registration("ba_49", "ba", "2026-10-09", "ba_49: truncate utility."),
    _registration("ba_50", "ba", "2026-10-09", "ba_50: pad2 utility."),
    _registration("backdoor", "runtime", "2026-10-08", "Backdoor testing and detection ledger, Simulated."),
    _registration("backdoor_detection", "runtime", "2026-10-08", "Backdoor detection decision ledger: scan, quarantine, report."),
    _registration("backdoor_detector", "runtime", "2026-10-07", "Backdoor trigger detector: runtime tripwire for neural backdoor triggers."),
    _registration("backpressure", "runtime", "2026-10-07", "Backpressure: reactive-streams demand signaling for a bounded agent pipeline."),
    _registration("backup_manager", "runtime", "2026-10-08", "Backup manager: snapshot/restore/schedule bookkeeping."),
    _registration("bandit_algorithm", "runtime", "2026-10-08", "Multi-armed bandit (arm/pull/reward) interface, simulated."),
    _registration("barcode_scanner", "runtime", "2026-10-08", "Barcode / 2D-code scanner interface (QR / DataMatrix shaped, simulated)."),
    _registration("bash_parser", "p1 seg1: bash_parser skeleton - verdict types, pre-parse checks,", "2026-11-06", "Hand-written recursive-descent Bash AST parser for security checks."),
    _registration("batch_processing", "runtime", "2026-10-08", "Batch processing: Spark/Airflow-shaped batch data-job bookkeeping."),
    _registration("bcp", "runtime", "2026-10-08", "Business continuity plan (BCP) governance ledger."),
    _registration("bdd_interface", "runtime", "2026-10-07", "Binary decision diagrams: reduced ordered BDDs for boolean functions."),
    _registration("benchmark", "runtime", "2026-10-08", "Benchmarks as a deterministic single-host decision ledger."),
    _registration("benchmark_retirement_probes", "runtime", "2026-10-07", "Benchmark-retirement probe corpus + retirement detection / revalidation gates."),
    _registration("benchmark_runner", "runtime", "2026-10-08", "Hyperfine-style benchmark bookkeeping."),
    _registration("beneficial_ai", "runtime", "2026-10-08", "Beneficial AI: beneficial-AI governance ledger, Simulated."),
    _registration("bft_interface", "runtime", "2026-10-07", "Byzantine fault tolerance interface: PBFT pre-prepare/prepare/commit bookkeeping."),
    _registration("bias_mock", "bias-mock", "2026-10-09", "Bias detection mock (D-OUT-010), Simulated."),
    _registration("bidi_remove", "bidi-remove", "2026-10-09", "Bidi control removal (D-IN-016), Simulated."),
    _registration("bilinear_accumulator", "runtime", "2026-10-07", "Bilinear accumulator interface: pairing-based set commitments (simulated)."),
    _registration("billing_engine", "runtime", "2026-10-08", "Billing engine: metered usage, tiered pricing, invoices, and proration (simulated)."),
    _registration("bipia_probe", "bipia-probe", "2026-10-09", "BIPIA probe: position-based injection (A7, Microsoft), Simulated."),
    _registration("blind_rerunner", "slice5", "2026-11-12", "Blind re-runner bundle and check-set comparison helpers."),
    _registration("bloom_filter", "runtime", "2026-10-07", "Probabilistic membership testing: a Bloom filter answers \"seen before?\" cheaply."),
    _registration("blue_green_deploy", "runtime", "2026-10-07", "Blue-green deployment controller: zero-downtime cutover between two versions."),
    _registration("booking_agents", "one-hundred-twenty-third", "2026-10-04", "Booking-agent transaction receipts (one-hundred-twenty-third batch)."),
    _registration("bot_manager", "runtime", "2026-10-08", "Good/bad bot management: allowlist, challenge, and block bookkeeping."),
    _registration("bpmn_engine", "runtime", "2026-10-08", "BPMN engine: process deployment and task-completion bookkeeping."),
    _registration("btree_index", "runtime", "2026-10-07", "B-tree: deterministic ordered key-value index for the runtime's own state."),
    _registration("budget", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Token budgets priced from real per-million rates, with prompt-cache accounting."),
    _registration("budget_approval_combo", "runtime", "2026-10-07", "Budget-gated approval: the budget is checked before a human is bothered."),
    _registration("budget_combo", "runtime", "2026-10-07", "Combined budget: per-call ceiling + token bucket, checked together."),
    _registration("budget_token_bucket", "runtime", "2026-10-07", "Token-bucket budget: rate-limited alternative to per-call ceilings."),
    _registration("bug_bounty", "runtime", "2026-10-08", "Bug-bounty decision ledger: submit, triage, reward."),
    _registration("bulkhead", "runtime", "2026-10-07", "Bulkhead fault isolation: one tenant's failure can never starve another."),
    _registration("bulkhead_pattern", "runtime", "2026-10-08", "Bulkhead pattern — isolation-compartment bookkeeping (resilience thirty-second batch)."),
    _registration("byzantine_agreement", "runtime", "2026-10-08", "Byzantine agreement: PBFT-shaped three-phase commit bookkeeping."),
    _registration("c2pa", "runtime", "2026-10-08", "C2PA (Coalition for Content Provenance and Authenticity) decision ledger, simulated."),
    _registration("cache_aside", "runtime", "2026-10-08", "Cache-aside (lazy-loading) pattern: application-managed cache/origin coherence."),
    _registration("cache_stampede", "runtime", "2026-10-08", "Cache-stampede (thundering-herd) protection: single-flight + jitter."),
    _registration("cache_tier", "runtime", "2026-10-07", "Multi-level cache: LRU/LFU eviction policies with deterministic bookkeeping."),
    _registration("calendar_service", "runtime", "2026-10-08", "Calendar service: CalDAV-shaped event/freebusy/RSVP bookkeeping."),
    _registration("canary_controller", "runtime", "2026-10-07", "Canary deployment controller: deterministic traffic splitting for safe rollout."),
    _registration("canary_tokens", "canary-tokens", "2026-10-09", "Canary tokens: deception for exfiltration detection (D-OUT-005), Simulated."),
    _registration("cancellation_tombstone", "tombstone", "2026-11-14", "Cancellation tombstones: sticky revocation state that survives compaction."),
    _registration("cancellation_view", "cancellation-visibility", "2026-11-17", "One rendering of a cancellation record, shared by every transcript read path."),
    _registration("canonical_json", "ninety-fifth", "2026-10-04", "JSON Canonicalization Scheme (RFC 8785) — the single canonicalizer."),
    _registration("capability_ceiling_probe", "capability-ceiling-probe", "2026-11-14", "Capability-ceiling probe: fail-first admission, calibration error, ceiling routing."),
    _registration("capability_eval", "runtime", "2026-10-08", "Capability testing (probe/measure/profile) interface, simulated."),
    _registration("capability_reassembly", "runtime", "2026-10-07", "Capability reassembly detector: benign calls that chain into a denied capability."),
    _registration("capability_warrants", "identity/mandate/warrant primitives (e+f lines) + refusal-qualit", "2026-10-05", "Tenuo-inspired capability warrants: holder-bound, attenuating, audited."),
    _registration("capacity_planning", "runtime", "2026-10-08", "Capacity planning: utilization ledger, forecasts, rightsizing recommendations."),
    _registration("captcha_mock", "captcha-mock", "2026-10-09", "CAPTCHA mock (D-IN-025), Simulated."),
    _registration("case_norm", "case-norm", "2026-10-09", "Case normalization (D-IN-019), Simulated."),
    _registration("cci_detector", "runtime", "2026-10-07", "Cryptographic Context Injection (CCI) detector."),
    _registration("ccpa", "runtime", "2026-10-08", "CCPA: California Consumer Privacy Act consumer-rights decision ledger."),
    _registration("cd_deployer", "runtime", "2026-10-07", "CD deployer: progressive-delivery orchestration as a deterministic state machine."),
    _registration("cdn_manager", "runtime", "2026-10-08", "CDN cache purge and prefetch bookkeeping."),
    _registration("cep_engine", "runtime", "2026-10-07", "Complex event processing: sequence-pattern matching over event streams."),
    _registration("cert_manager", "runtime", "2026-10-07", "Certificate manager: cert-manager-style issuance, renewal, and revocation (simulated)."),
    _registration("chain_of_thought", "runtime", "2026-10-08", "Chain-of-thought reasoning (reason/trace) interface, simulated."),
    _registration("change_data_capture", "runtime", "2026-10-08", "Change data capture: Debezium-shaped change-event bookkeeping."),
    _registration("changelog", "runtime", "2026-10-07", "Changelog: append-only op log for state recovery."),
    _registration("changelog_generator", "runtime", "2026-10-08", "Changelog generator interface (conventional-commits shaped, simulated)."),
    _registration("chaos_engineering", "runtime", "2026-10-08", "Chaos engineering — simulated fault-injection experiment bookkeeping."),
    _registration("chaos_experiment", "runtime", "2026-10-07", "Chaos experiment interface: fault-injection bookkeeping as a deterministic state machine."),
    _registration("checkpoint_durability", "langgraph-durability", "2026-11-14", "Checkpoint durability modes: *when* a checkpoint reaches disk."),
    _registration("checkpoint_store", "msaf-lineage", "2026-11-13", "Atomic, path-safe checkpoint storage."),
    _registration("checkpoints", "add turn-boundary checkpoints, and close the hole where resume r", "2026-09-08", "Turn-boundary checkpoints: resume without resetting the counters, fork without rewriting."),
    _registration("ci_pipeline", "runtime", "2026-10-07", "CI pipeline: GitHub-Actions-style stage/job bookkeeping."),
    _registration("circuit", "runtime", "2026-10-08", "Circuit: mechanistic-interpretability circuit discovery / verification / ablation ledger."),
    _registration("circuit_breaker", "runtime", "2026-10-07", "Circuit breaker: fail-fast gate for an unreliable operation."),
    _registration("cirl", "runtime", "2026-10-08", "Cooperative Inverse Reinforcement Learning (CIRL) decision ledger, Simulated."),
    _registration("citation_verify", "citation-verify", "2026-10-09", "Citation verification (D-OUT-013), Simulated."),
    _registration("claimed_auth_corpus", "bench", "2026-10-06", "Claimed-authorization probe corpus for the governance bench."),
    _registration("cli", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Command-line entry point for the Northstar Agent OS."),
    _registration("cmdi_detect", "cmdi-detect", "2026-10-09", "Command injection detection (D-OUT-025), Simulated."),
    _registration("cmmc", "runtime", "2026-10-08", "CMMC certification decision ledger: systems, practice assessments, POA&M, certification."),
    _registration("coap_server", "runtime", "2026-10-08", "CoAP server: simulated RFC 7252 constrained-application-protocol ledger."),
    _registration("code_formatter", "runtime", "2026-10-08", "Code formatter: Black-style formatting bookkeeping."),
    _registration("code_scan", "code-scan", "2026-10-09", "Code output scanning (D-OUT-022), Simulated."),
    _registration("code_signer", "runtime", "2026-10-08", "Code signing interface (Sigstore / Fulcio / Cosign shaped, simulated)."),
    _registration("code_task", "add verified code-task workflow and offline benchmark pack", "2026-10-13", "Isolated Git workspaces and evidence artifacts for ``northstar code``."),
    _registration("coerce_guard", "coerce-guard", "2026-10-09", "Type coercion guards (D-IN-029), Simulated."),
    _registration("column_store", "runtime", "2026-10-08", "Column store: Cassandra-shaped wide-column bookkeeping ledger."),
    _registration("command_hooks", "close the governance seams found by the 2026-09 capability audit", "2026-09-08", "Repository-declared lifecycle hooks: the governed subset of a \"command hook\"."),
    _registration("command_registry", "command-registry", "2026-10-08", "Command registry with bounded pre-authorization (AutoGPT), Simulated."),
    _registration("commerce", "one-hundred-twenty-fourth", "2026-10-04", "Agentic commerce terms (one-hundred-twenty-fourth batch)."),
    _registration("commerce_mandate_probes", "runtime", "2026-10-07", "Agentic-commerce mandate probe corpus + forged / replay / amount-switch probes."),
    _registration("compaction", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Context compaction that only ever cuts at a safe boundary."),
    _registration("compaction_approval_combo", "runtime", "2026-10-07", "Compaction guard that never masks approval receipts."),
    _registration("compaction_masking", "runtime", "2026-10-07", "Observation masking for conversation compaction."),
    _registration("companionship", "one-hundred-twenty-first", "2026-10-04", "Companionship safeguards (one-hundred-twenty-first batch)."),
    _registration("compliance", "runtime", "2026-10-08", "Compliance governance ledger: frameworks, control checks, remediation, attestation."),
    _registration("compliance_checker", "runtime", "2026-10-08", "compliance_checker.py — SOC2 control verification bookkeeping."),
    _registration("compliance_reports", "runtime", "2026-10-08", "Compliance reports: SOC 2 / ISO 27001 report, evidence, and attestation bookkeeping."),
    _registration("compute_budget", "one-hundred-ninth", "2026-10-04", "Compute-budget receipts (one-hundred-ninth batch)."),
    _registration("confidence_calib", "confidence-calib", "2026-10-09", "Confidence calibration mock (D-OUT-015), Simulated."),
    _registration("confidence_gate", "confidence-gate", "2026-10-08", "Confidence-gated authorization (D11, AlphaFold pLDDT), Simulated."),
    _registration("confidential_compute", "runtime", "2026-10-08", "Confidential compute workload ledger (SGX / SEV-SNP / TDX, simulated)."),
    _registration("confidential_vm", "runtime", "2026-10-07", "Confidential VM interface (AMD SEV-SNP / Intel TDX, simulated)."),
    _registration("config_management", "runtime", "2026-10-08", "Config KV store bookkeeping: a ledger for configuration decisions."),
    _registration("config_server", "runtime", "2026-10-07", "Spring-Cloud-Config-shaped central configuration server bookkeeping."),
    _registration("conformity", "runtime", "2026-10-08", "EU conformity-assessment / CE-marking-shaped decision ledger."),
    _registration("confusable_detect", "confusable-detect", "2026-10-09", "Confusable detection (D-IN-012), Simulated."),
    _registration("congestion_control", "runtime", "2026-10-07", "BBR-style congestion controller over simulated, caller-supplied time."),
    _registration("connection_pool", "runtime", "2026-10-07", "Connection pool: bounded acquire/release bookkeeping for reusable connections."),
    _registration("connector_sdk", "runtime", "2026-10-08", "Connector SDK (plugin interface) bookkeeping, simulated."),
    _registration("consensus_interface", "runtime", "2026-10-07", "Consensus protocol interface: propose/accept/commit bookkeeping."),
    _registration("consent_manager", "runtime", "2026-10-08", "GDPR consent manager (twenty-eighth batch)."),
    _registration("consent_receipts", "one-hundred-fifth", "2026-10-04", "Revocable consent receipts (one-hundred-fifth batch)."),
    _registration("consistent_hash", "runtime", "2026-10-07", "Consistent hashing: deterministic key-to-node routing for sharded work."),
    _registration("consistent_hashing", "runtime", "2026-10-08", "Consistent hashing — Dynamo-ring node bookkeeping."),
    _registration("constitutional_ai", "runtime", "2026-10-08", "ConstitutionalAI: principle-directed self-critique/revise bookkeeping."),
    _registration("constitutional_monitor", "runtime", "2026-10-07", "Constitutional AI monitor: principle-based violation tripwire."),
    _registration("constraint_synthesis_probes", "runtime", "2026-10-07", "Constraint-synthesis probes: AgentRx-style executable invariants from tool schemas."),
    _registration("construction_agents", "one-hundred-sixtieth", "2026-10-04", "Construction-site AI discipline (one-hundred-sixtieth batch)."),
    _registration("contacts_manager", "runtime", "2026-10-08", "CardDAV-shaped contact management, in-memory."),
    _registration("container_registry", "runtime", "2026-10-07", "Container registry: OCI distribution-spec-shaped image bookkeeping."),
    _registration("content_authenticity", "runtime", "2026-10-08", "content_authenticity.py — content-authenticity signature bookkeeping."),
    _registration("content_filter", "content-filter", "2026-10-09", "Content filtering: blocklist (D-OUT-008), Simulated."),
    _registration("content_moderator", "runtime", "2026-10-08", "Content moderation interface (twenty-ninth batch)."),
    _registration("context_budget", "fable", "2026-11-13", "Context-engineering thresholds for Northstar's own context path."),
    _registration("context_controller", "fable", "2026-11-13", "The stateful half of the context-engineering rules."),
    _registration("context_window", "runtime", "2026-10-08", "Context window: token-budget bookkeeping for a bounded message window."),
    _registration("contract_bridge", "close the governance seams found by the 2026-09 capability audit", "2026-09-08", "One source of truth for the runtime → sidecar wire format, checked against the Run Contract."),
    _registration("contract_tester", "runtime", "2026-10-08", "Consumer-driven contract tester (Pact style, simulated)."),
    _registration("control_testing", "runtime", "2026-10-08", "Control testing ledger: design, operate, test, remediate controls."),
    _registration("controllable_ai", "runtime", "2026-10-08", "Controllable AI: AI controllability governance decision ledger, Simulated."),
    _registration("cooperative_irl", "runtime", "2026-10-08", "Cooperative IRL decision ledger for human-robot team alignment, Simulated."),
    _registration("coppa", "runtime", "2026-10-08", "COPPA: Children's Online Privacy Protection Act compliance decision ledger, Simulated."),
    _registration("corrigibility", "runtime", "2026-10-08", "Corrigibility: declared-agent corrigibility check / preservation bookkeeping ledger."),
    _registration("cost_optimization", "runtime", "2026-10-08", "Cost optimization — CloudHealth-shaped spend analysis bookkeeping (thirty-fourth batch)."),
    _registration("cost_per_delivery", "cost-per-delivery", "2026-11-14", "Cost per delivery: quote a slice's budget per *verified delivery*."),
    _registration("count_min_sketch", "runtime", "2026-10-07", "Count-min sketch: compact frequency estimation for event streams."),
    _registration("counterfactual", "runtime", "2026-10-10", "Pinned, non-generative explanations for selected runtime denial rules."),
    _registration("counterfactual_explanation_probes", "runtime", "2026-10-07", "Counterfactual-explanation probes: quality gates for explanation surfaces."),
    _registration("coverage_manifest", "lightningzero", "2026-11-14", "Coverage manifest and intake audit: the layer under the blind re-runner."),
    _registration("coverage_reporter", "runtime", "2026-10-08", "Coverage reporter: simulated coverage.py-style measurement bookkeeping."),
    _registration("cqrs", "runtime", "2026-10-08", "Command Query Responsibility Segregation (CQRS) ledger."),
    _registration("cqrs_pattern", "runtime", "2026-10-07", "Command Query Responsibility Segregation (CQRS) dispatch point."),
    _registration("crdt_counter", "runtime", "2026-10-08", "CRDT counter — state-based PN-counter bookkeeping (thirty-sixth batch)."),
    _registration("crdt_interface", "runtime", "2026-10-07", "CRDT interface: grow-only and PN counters for eventually consistent replicas."),
    _registration("crdt_map", "runtime", "2026-10-08", "CRDT map: observed-remove map for eventually consistent replicas."),
    _registration("crdt_set", "runtime", "2026-10-08", "CRDT set: observed-remove set (OR-Set) for eventually consistent replicas."),
    _registration("credential_detector", "runtime", "2026-10-07", "Hardcoded credential detector for MCP configs and agent surfaces."),
    _registration("crescendo_probe", "crescendo-probe", "2026-10-09", "Crescendo probe: multi-turn gradual escalation (A5, Microsoft), Simulated."),
    _registration("crisis_management", "runtime", "2026-10-08", "Crisis management bookkeeping (declare / coordinate / report / standdown)."),
    _registration("critique_model", "runtime", "2026-10-08", "Critique-model ledger: declare AI/human critiques of model outputs, Simulated."),
    _registration("cron_scheduler", "runtime", "2026-10-08", "Cron scheduler — cron schedule ownership as a deterministic state machine."),
    _registration("crypto_agility", "probes", "2026-10-07", "Crypto-agility seam for digital signatures."),
    _registration("crypto_defense_01", "massive", "2026-10-09", "Crypto Defense 01: Sigstore interface (mock), Simulated."),
    _registration("crypto_defense_02", "massive", "2026-10-09", "Crypto Defense 02: Cosign verification (mock), Simulated."),
    _registration("crypto_defense_03", "massive", "2026-10-09", "Crypto Defense 03: Rekor transparency log (mock), Simulated."),
    _registration("crypto_defense_04", "massive", "2026-10-09", "Crypto Defense 04: Fulcio certificates (mock), Simulated."),
    _registration("crypto_defense_05", "massive", "2026-10-09", "Crypto Defense 05: Threshold signatures 2-of-3 (mock), Simulated."),
    _registration("crypto_defense_06", "worker", "2026-10-09", "Crypto Defense 06: MPC for keys (mock), Simulated."),
    _registration("crypto_defense_07", "worker", "2026-10-09", "Crypto Defense 07: HSM integration (mock), Simulated."),
    _registration("crypto_defense_08", "worker", "2026-10-09", "Crypto Defense 08: Key rotation (mock), Simulated."),
    _registration("crypto_defense_09", "worker", "2026-10-09", "Crypto Defense 09: Forward secrecy (mock), Simulated."),
    _registration("crypto_defense_10", "worker", "2026-10-09", "Crypto Defense 10: Post-quantum KEM (mock Kyber-like), Simulated."),
    _registration("crypto_defense_11", "worker", "2026-10-09", "Crypto Defense 11: Hybrid schemes (classical + PQ), Simulated."),
    _registration("crypto_defense_12", "worker", "2026-10-09", "Crypto Defense 12: ZK proofs (mock), Simulated."),
    _registration("crypto_defense_13", "worker", "2026-10-09", "Crypto Defense 13: OPRF screening (mock), Simulated."),
    _registration("crypto_defense_14", "worker", "2026-10-09", "Crypto Defense 14: PIR for lookups (mock), Simulated."),
    _registration("crypto_defense_15", "worker", "2026-10-09", "Crypto Defense 15: Homomorphic encryption (mock), Simulated."),
    _registration("crypto_defense_16", "worker", "2026-10-09", "Crypto Defense 16: Secure enclaves (mock attestation), Simulated."),
    _registration("crypto_defense_17", "worker", "2026-10-09", "Crypto Defense 17: Remote attestation (mock), Simulated."),
    _registration("crypto_defense_18", "worker", "2026-10-09", "Crypto Defense 18: Measured boot (mock), Simulated."),
    _registration("crypto_defense_19", "worker", "2026-10-09", "Crypto Defense 19: TPM integration (mock), Simulated."),
    _registration("crypto_defense_20", "worker", "2026-10-09", "Crypto Defense 20: Hardware tokens (mock), Simulated."),
    _registration("crypto_defense_21", "worker", "2026-10-09", "Crypto Defense 21: Biometric auth (mock), Simulated."),
    _registration("crypto_defense_22", "worker", "2026-10-09", "Crypto Defense 22: WebAuthn (mock), Simulated."),
    _registration("crypto_defense_23", "worker", "2026-10-09", "Crypto Defense 23: Passkeys (mock), Simulated."),
    _registration("crypto_defense_24", "worker", "2026-10-09", "Crypto Defense 24: OIDC integration (mock), Simulated."),
    _registration("crypto_defense_25", "worker", "2026-10-09", "Crypto Defense 25: SAML integration (mock), Simulated."),
    _registration("crypto_defense_26", "worker", "2026-10-09", "Crypto Defense 26: OAuth scopes (scope checker), Simulated."),
    _registration("crypto_defense_27", "worker", "2026-10-09", "Crypto Defense 27: JWT validation (mock with HMAC), Simulated."),
    _registration("crypto_defense_28", "worker", "2026-10-09", "Crypto Defense 28: Token binding (mock), Simulated."),
    _registration("crypto_defense_29", "worker", "2026-10-09", "Crypto Defense 29: DPoP (mock), Simulated."),
    _registration("crypto_defense_30", "worker", "2026-10-09", "Crypto Defense 30: mTLS client certs (mock), Simulated."),
    _registration("csv_processor", "runtime", "2026-10-08", "CSV parse/emit/validate interface (RFC 4180 bookkeeping)."),
    _registration("ctrl_strip", "ctrl-strip", "2026-10-09", "Control char stripping (D-IN-006), Simulated."),
    _registration("currency_converter", "runtime", "2026-10-08", "Currency converter interface: FX rate table with exact-rational conversion."),
    _registration("custom_domains", "runtime", "2026-10-08", "Custom domains: map / verify / ssl (simulated domain mapping interface)."),
    _registration("dag_scheduler", "runtime", "2026-10-08", "DAG scheduler: Airflow-shaped task-graph bookkeeping as a deterministic state machine."),
    _registration("dast_scanner", "runtime", "2026-10-08", "DAST scanner: crawl x attack-template bookkeeping (OWASP ZAP shaped, simulated)."),
    _registration("data_catalog", "runtime", "2026-10-08", "Amundsen-shaped data catalog: a ledger for dataset/schema decisions."),
    _registration("data_deletion", "runtime", "2026-10-08", "GDPR right to erasure: request/verify/execute deletion ledger (simulated)."),
    _registration("data_exfiltration", "runtime", "2026-10-08", "Data exfiltration detection/prevention ledger: book declared egress signals."),
    _registration("data_export", "runtime", "2026-10-08", "Data export (GDPR portability): request / status / download."),
    _registration("data_extraction", "runtime", "2026-10-08", "Data-extraction attack/defense decision ledger, Simulated."),
    _registration("data_lineage", "runtime", "2026-10-07", "Provenance DAG for ML data: which datasets derived from which sources."),
    _registration("data_pipeline", "runtime", "2026-10-08", "Data pipeline (ETL/ELT interface, thirtieth batch)."),
    _registration("data_poisoning_detector", "runtime", "2026-10-07", "Training data poisoning detector: catch backdoors before they train."),
    _registration("data_residency", "runtime", "2026-10-08", "Data residency: regional storage pinning and cross-border transfer control (simulated)."),
    _registration("data_sync", "runtime", "2026-10-08", "Bidirectional data synchronization (thirtieth batch)."),
    _registration("data_validation", "runtime", "2026-10-08", "Data validation: deterministic expectation-suite bookkeeping."),
    _registration("data_versioning", "runtime", "2026-10-08", "Data versioning — DVC/LakeFS-shaped dataset snapshot bookkeeping."),
    _registration("dataflow_policy", "dataflow sensitivity tracking + deterministic toml policy (opena", "2026-10-04", "Dataflow sensitivity tracking with a deterministic TOML policy."),
    _registration("dataset_version", "runtime", "2026-10-07", "DVC-style dataset versioning: content-addressed commits, diffs, checkouts."),
    _registration("datasheet", "runtime", "2026-10-08", "Dataset datasheets: Gebru et al."),
    _registration("dating_agents", "one-hundred-sixty-third", "2026-10-04", "Dating & relationships AI discipline (one-hundred-sixty-third batch)."),
    _registration("ddos_protection", "runtime", "2026-10-08", "DDoS attack detection and mitigation bookkeeping."),
    _registration("dead_letter", "runtime", "2026-10-07", "Dead-letter queue interface (poison-message handling, simulated)."),
    _registration("dead_letter_queue", "runtime", "2026-10-08", "Dead letter queue: failed-message lifecycle bookkeeping."),
    _registration("debate", "runtime", "2026-10-08", "AI safety via debate (argue/judge/transcript) interface, simulated."),
    _registration("debate_protocol", "runtime", "2026-10-07", "Debate protocol: AI safety via adversarial argumentation."),
    _registration("debugger", "runtime", "2026-10-07", "Delve-style debugger interface as a deterministic state machine."),
    _registration("deception", "runtime", "2026-10-08", "Deception: honeypot deception-operations ledger, Simulated."),
    _registration("deception_detector", "runtime", "2026-10-07", "Deceptive reasoning detector: false claims, evidence concealment, source fabrication."),
    _registration("deceptive_alignment", "runtime", "2026-10-08", "Deceptive alignment as a deterministic single-host decision ledger."),
    _registration("decision_model", "bench", "2026-10-04", "Structured decision-model approval path (SystemOne-style)."),
    _registration("decision_table", "runtime", "2026-10-08", "Decision table: DMN-shaped rule bookkeeping."),
    _registration("deepfake_detection", "runtime", "2026-10-08", "DeepfakeDetection: synthetic-media detection decision bookkeeping for agents."),
    _registration("def_extra_01", "worker", "2026-10-09", "Behavioral biometrics gate (mock), Simulated."),
    _registration("def_extra_02", "worker", "2026-10-09", "Device fingerprinting gate (mock), Simulated."),
    _registration("def_extra_03", "worker", "2026-10-09", "Geofencing gate, Simulated."),
    _registration("def_extra_04", "worker", "2026-10-09", "Time-based access control, Simulated."),
    _registration("def_extra_05", "worker", "2026-10-09", "Risk scoring engine, Simulated."),
    _registration("def_extra_06", "worker", "2026-10-09", "Adaptive authentication (mock), Simulated."),
    _registration("def_extra_07", "worker", "2026-10-09", "Step-up authentication (mock), Simulated."),
    _registration("def_extra_08", "worker", "2026-10-09", "Transaction signing (mock), Simulated."),
    _registration("def_extra_09", "worker", "2026-10-09", "Audit trail verification, Simulated."),
    _registration("def_extra_10", "worker", "2026-10-09", "Log integrity via hash chain, Simulated."),
    _registration("def_extra_11", "worker", "2026-10-09", "Tamper detection for sealed blobs (mock), Simulated."),
    _registration("def_extra_12", "worker", "2026-10-09", "Secure timestamping authority (mock), Simulated."),
    _registration("def_extra_13", "worker", "2026-10-09", "Non-repudiation receipts (mock), Simulated."),
    _registration("def_extra_14", "worker", "2026-10-09", "Digital signature verification (mock), Simulated."),
    _registration("def_extra_15", "worker", "2026-10-09", "Certificate Transparency enforcement (mock), Simulated."),
    _registration("def_extra_16", "worker", "2026-10-09", "OCSP stapling check (mock), Simulated."),
    _registration("def_extra_17", "worker", "2026-10-09", "CRL checking (mock), Simulated."),
    _registration("def_extra_18", "worker", "2026-10-09", "Pinning violation detection (HPKP-style), Simulated."),
    _registration("def_extra_19", "worker", "2026-10-09", "Downgrade attack detection, Simulated."),
    _registration("def_extra_20", "worker", "2026-10-09", "Protocol version enforcement, Simulated."),
    _registration("defense_agents", "one-hundred-sixty-fifth", "2026-10-04", "Defense & dual-use AI discipline gates (one-hundred-sixty-fifth batch)."),
    _registration("defensive_agent", "add defensive agent assessment layer", "2026-10-16", "Deterministic blue-team assessment for agent inputs and tool targets."),
    _registration("delay_queue", "runtime", "2026-10-08", "Delay queue: delayed-task delivery bookkeeping."),
    _registration("delegation_credentials", "biscuit-style attenuating delegation credentials (seventieth bat", "2026-10-04", "Biscuit-style attenuating delegation credentials (minimal subset)."),
    _registration("deliberative_spec", "deliberative-spec", "2026-10-08", "Deliberative spec citation (D12, OpenAI), Simulated."),
    _registration("deny_hotpath", "c54", "2026-11-12", "Hot-path deny lookup: one indexed read against a revocation counter."),
    _registration("deny_monotonicity", "bench", "2026-10-07", "Deny-monotonicity check for the governance bench."),
    _registration("dependency_resolver", "runtime", "2026-10-08", "Package dependency resolver: constraint solving as deterministic bookkeeping."),
    _registration("deployment_registry", "one-hundred-tenth", "2026-10-04", "Deployment registration gate (one-hundred-tenth batch)."),
    _registration("deser_guard", "deser-guard", "2026-10-09", "Deserialization guard (D-OUT-029), Simulated."),
    _registration("destructive_prefix_probes", "runtime", "2026-10-07", "Destructive-prefix probes: the tool name is an attack surface."),
    _registration("deterministic_gate_score", "deterministic-gate-score", "2026-11-14", "Deterministic gate-and-score ledger with a three-state case outcome."),
    _registration("deterministic_veto", "deterministic-veto", "2026-10-08", "Deterministic veto: model can escalate, never waive (D2), Simulated."),
    _registration("developer_portal", "runtime", "2026-10-08", "Developer portal: ReadMe / Backstage-shaped API docs + console bookkeeping (simulated)."),
    _registration("device_manager", "runtime", "2026-10-08", "Device manager: trusted-device enrollment, verification, and revocation (simulated)."),
    _registration("differential_privacy", "runtime", "2026-10-08", "Differential privacy bookkeeping."),
    _registration("disaster_agents", "one-hundred-thirty-seventh", "2026-10-04", "Emergency-response discipline receipts (one-hundred-thirty-seventh batch)."),
    _registration("disaster_recovery", "runtime", "2026-10-08", "Disaster recovery: DR plans, failover events, and drill bookkeeping."),
    _registration("distributed_consensus", "runtime", "2026-10-08", "Distributed consensus round coordinator: propose/vote/commit bookkeeping."),
    _registration("distributed_lock", "runtime", "2026-10-07", "Distributed lock manager: mutual exclusion with monotonic fencing tokens."),
    _registration("distributed_tracing", "runtime", "2026-10-08", "Distributed tracing: Jaeger/Zipkin-shaped span and trace bookkeeping."),
    _registration("dkg_interface", "runtime", "2026-10-07", "Distributed key generation interface: Pedersen DKG bookkeeping (simulated)."),
    _registration("dlp_interface", "dlp-interface", "2026-10-09", "DLP integration: data loss prevention interface (D-OUT-003), Simulated."),
    _registration("dns_manager", "runtime", "2026-10-08", "DNS manager — simulated authoritative-DNS bookkeeping (Route53/Cloudflare shaped)."),
    _registration("dns_resolver", "runtime", "2026-10-07", "DNS record bookkeeping with TTL expiry — a deterministic resolver ledger."),
    _registration("doc_converter", "runtime", "2026-10-08", "Pandoc-style document format conversion, in-memory."),
    _registration("doc_scanner", "runtime", "2026-10-08", "Document scanner: simulated edge/corner detection and enhancement bookkeeping."),
    _registration("docker_interface", "runtime", "2026-10-07", "Docker interface: container lifecycle bookkeeping (build / run / stop)."),
    _registration("doctor", "dx foundations", "2026-09-07", "Environment self-checks behind ``cli doctor``."),
    _registration("document_store", "runtime", "2026-10-07", "MongoDB-style document store: CRUD plus single-field indexes, in-memory."),
    _registration("dp_accountant", "runtime", "2026-10-07", "Differential privacy budget accounting for training pipelines."),
    _registration("dp_interface", "runtime", "2026-10-07", "Differential-privacy mechanisms: Laplace and Gaussian noise, with composition."),
    _registration("dpo", "runtime", "2026-10-08", "DPO: Direct Preference Optimization bookkeeping for agents."),
    _registration("drift_probe", "ninetieth", "2026-10-04", "Post-release drift detection (ninetieth batch)."),
    _registration("dual_use", "one-hundred-eleventh", "2026-10-04", "Dual-use screen for autonomous science (one-hundred-eleventh batch)."),
    _registration("durable_bridge", "runtime", "2026-09-08", "One run boundary, two readers: the runtime checkpoint in durable-run's vocabulary."),
    _registration("durable_resume", "langgraph", "2026-11-13", "Durable checkpoints, retry-clears-writes, and an explicit resume command."),
    _registration("ed25519", "audit", "2026-10-03", "Minimal pure-Python Ed25519 (RFC 8032), vendored."),
    _registration("edge_compute", "runtime", "2026-10-08", "Edge-function deploy/invoke bookkeeping: a ledger for edge compute decisions."),
    _registration("edge_gate", "runtime", "2026-10-07", "Physical/irreversible dispatch edge gate: a human at the boundary."),
    _registration("edge_gate_ml", "runtime", "2026-10-07", "Edge gate, ML-style variant: continuous risk scoring instead of rule tiers."),
    _registration("edge_memory_combo", "runtime", "2026-10-07", "Edge gate + bitemporal memory integration: risk context from the past."),
    _registration("editorial", "batch-117", "2026-10-04", "Editorial countersign + publication gates (one-hundred-seventeenth batch)."),
    _registration("education_agents", "one-hundred-fifty-first", "2026-10-04", "Education AI discipline gates (one-hundred-fifty-first batch)."),
    _registration("effect_directive", "effect-directive", "2026-11-14", "Typed effect envelope: pure ``decide``, host-only minting, runtime execution."),
    _registration("effort_scaling", "anthropic-effort-scaling", "2026-11-14", "Effort scaling: task complexity -> parallelism budget (orchestrator-worker)."),
    _registration("egress_client", "egress gateway", "2026-10-04", "Agent-side client for the egress sidecar."),
    _registration("egress_enforcer", "egress gateway", "2026-10-04", "Deterministic egress policy engine: the enforcement half of the gateway."),
    _registration("egress_proxy", "runtime", "2026-10-08", "Egress forward-proxy policy: destination allowlist and request filtering."),
    _registration("egress_scope", "harden agent runtime security and red-team governance", "2026-10-12", "Canonical, bounded host sets for host-owned per-run egress scope."),
    _registration("eldercare_agents", "one-hundred-sixty-first", "2026-10-04", "Elder-care AI discipline (one-hundred-sixty-first batch)."),
    _registration("email_service", "runtime", "2026-10-08", "Email service interface: SendGrid/SES/Mailgun-shaped transactional email bookkeeping."),
    _registration("embodied", "one-hundred-twenty-sixth", "2026-10-04", "Embodied-AI safety vacuum gates (one-hundred-twenty-sixth batch)."),
    _registration("enclave_interface", "runtime", "2026-10-07", "Secure enclave interface: SGX / SEV-SNP / TDX attestation and sealed execution."),
    _registration("encoding_norm", "encoding-norm", "2026-10-09", "Encoding normalization (D-IN-004), Simulated."),
    _registration("encryption_at_rest", "runtime", "2026-10-08", "Encryption at rest: envelope-encrypted store interface."),
    _registration("endpoint_identity", "neo-konsi-s2bw", "2026-11-14", "Destination identity by state epoch, for endpoint-switch idempotency."),
    _registration("energybid_agents", "one-hundred-forty-fifth", "2026-10-04", "Energy trading discipline (one-hundred-forty-fifth batch)."),
    _registration("enforcement_gap_probes", "runtime", "2026-10-07", "Enforcement-gap probes (formal twin of the P0 wiring rule)."),
    _registration("env_cost", "one-hundred-fifteenth", "2026-10-04", "Environmental-cost receipts (one-hundred-fifteenth batch)."),
    _registration("episode_eviction", "cwl-episode-eviction", "2026-11-14", "CWL structured context eviction: typed episodes, dependency DAG, and a deterministic graduated eviction policy."),
    _registration("escrow_service", "runtime", "2026-10-08", "Escrow service interface: hold/release/dispute bookkeeping."),
    _registration("ethics_review", "runtime", "2026-10-08", "Ethics review board (submit/adjudicate/appeal) interface, simulated."),
    _registration("evaluation", "runtime", "2026-10-08", "Evaluation: AI capability/safety evaluation governance ledger, Simulated."),
    _registration("evaluation_harness", "runtime", "2026-10-08", "LLM eval-harness (suite/score/report) interface, simulated."),
    _registration("evaluator_access", "one-hundred-thirteenth", "2026-10-04", "Evaluator-access receipts and cheat probes (one-hundred-thirteenth batch)."),
    _registration("evasion_corpus", "governance", "2026-10-06", "Evasion probe corpus for the governance bench."),
    _registration("evasion_defense", "runtime", "2026-10-08", "Evasion-attack defense decision ledger."),
    _registration("event_bridge", "runtime", "2026-10-08", "Event bridge interface (event routing with input transformation, simulated)."),
    _registration("event_catalog", "runtime", "2026-10-08", "AsyncAPI-shaped event catalog: a ledger for event schema decisions."),
    _registration("event_condenser", "event-condenser", "2026-11-14", "Condensation as a first-class log event: the view is derived from the log."),
    _registration("event_sourcing", "runtime", "2026-10-07", "Event sourcing: append-only event log with replay for auditability."),
    _registration("events", "t1: python sdk embedding surface (sdk.py + events.py + example)", "2026-09-07", "Public event vocabulary of a governed run: dict events + result exit codes."),
    _registration("evidence_aging_probes", "runtime", "2026-10-07", "Evidence-aging probe corpus + freshness / decay detectors + aging gates."),
    _registration("evidence_compaction_probes", "runtime", "2026-10-07", "Evidence-compaction probe corpus + payload/evidence separation detectors."),
    _registration("evidence_independence", "evidence-independence", "2026-11-13", "Evidence independence: count independent origins, not hits."),
    _registration("evidence_tiers", "eighty-seventh", "2026-10-04", "Binary evidence tiers + LOG_DROP policy (eighty-seventh batch)."),
    _registration("exactly_once", "runtime", "2026-10-07", "Exactly-once processor: dedup ledger plus checkpoint/recovery for ordered streams."),
    _registration("excel_handler", "runtime", "2026-10-08", "Excel sheet/cell/formula content model and formula-evaluation contract, in-memory."),
    _registration("experiment_tracker", "runtime", "2026-10-07", "Experiment tracking interface (MLflow / Weights & Biases shape, simulated)."),
    _registration("experiment_tracking", "runtime", "2026-10-08", "Experiment tracking — simulated W&B-style run bookkeeping (thirty-third batch)."),
    _registration("exploit_difficulty", "runtime", "2026-10-07", "Exploit-difficulty recalibration from observed model attempts."),
    _registration("face_detector", "runtime", "2026-10-08", "Face detection interface (deterministic boxes, landmarks, attributes)."),
    _registration("factuality_mock", "factuality-mock", "2026-10-09", "Factuality checking mock (D-OUT-012), Simulated."),
    _registration("failure_budget_combo", "runtime", "2026-10-07", "Failure bundles for budget exhaustion: incident records with budget detail."),
    _registration("failure_bundle", "runtime", "2026-10-07", "Production failure bundles with incident state and recovery."),
    _registration("failure_detector", "runtime", "2026-10-08", "Failure detector: phi-accrual (Hayashibara et al."),
    _registration("fairness_eval", "runtime", "2026-10-08", "Fairness evaluation (bias testing) bookkeeping."),
    _registration("false_green_detector", "false-green-detector", "2026-11-14", "False-green detector: a success signal whose content fails validation."),
    _registration("fe_interface", "runtime", "2026-10-07", "Functional encryption interface (Boneh-Sahai-Waters style, simulated)."),
    _registration("feature_engineering", "runtime", "2026-10-08", "Feature engineering: deterministic transformation/encoding/scaling bookkeeping."),
    _registration("feature_flags", "runtime", "2026-10-07", "Feature flags for safe rollout: deterministic per-subject gating."),
    _registration("feature_store", "runtime", "2026-10-07", "Feature store interface: registered features, point-in-time serving, backfill."),
    _registration("feature_viz", "runtime", "2026-10-08", "Feature visualization: interpretability visualization decision ledger, Simulated."),
    _registration("federated_attack_detector", "runtime", "2026-10-07", "Federated-learning Byzantine attack detector: majority statistics, not trust."),
    _registration("federated_learning", "runtime", "2026-10-07", "Federated learning: FedAvg aggregation bookkeeping."),
    _registration("fedramp", "runtime", "2026-10-08", "FedRAMP (Federal Risk and Authorization Management Program) authorization ledger."),
    _registration("few_shot_learning", "runtime", "2026-10-08", "Few-shot / in-context learning example ledger, simulated."),
    _registration("fhe", "runtime", "2026-10-08", "FHE: fully-homomorphic-encryption decision ledger for agents."),
    _registration("fhe_interface", "runtime", "2026-10-07", "Fully homomorphic encryption interface (simulated)."),
    _registration("fhe_wrapper", "runtime", "2026-10-07", "Homomorphic-encryption wrapper (simulated interface)."),
    _registration("finance_agents", "one-hundred-fifty-fifth", "2026-10-04", "Finance AI discipline (one-hundred-fifty-fifth batch)."),
    _registration("finding_gate", "bughunter-finding-gate", "2026-11-21", "Finding gate: seven questions asked in order before a finding ships."),
    _registration("fingerprinting", "runtime", "2026-10-08", "Content fingerprinting: deterministic perceptual-hash-style ledger."),
    _registration("flag_service", "runtime", "2026-10-07", "LaunchDarkly-style feature flag service: targeting, rules, percentage rollouts."),
    _registration("flag_targeting", "runtime", "2026-10-08", "Advanced feature-flag targeting: rule engine, staged gradual rollouts, multi-variation."),
    _registration("floor_settings", "floor-settings", "2026-10-08", "Floor settings: unweakable policy minimums (D9, Google Model Armor), Simulated."),
    _registration("flow_control", "runtime", "2026-10-07", "TCP-style flow control: sliding-window send/ack bookkeeping."),
    _registration("forensics", "runtime", "2026-10-08", "DFIR evidence-acquisition ledger (digital forensics and incident response)."),
    _registration("forest_fish", "one-hundred-thirty-third", "2026-10-04", "Forest & fisheries evidence gates (one-hundred-thirty-third batch)."),
    _registration("formal_verif", "runtime", "2026-10-07", "Formal verification interface (explicit-state model checking, simulated)."),
    _registration("forward_seal_ledger", "forward-seal-ledger", "2026-10-08", "Forward-secure sealed decision ledger, Simulated."),
    _registration("fragile_watermark", "runtime", "2026-10-08", "Fragile watermark interface: tamper-evident marking for byte carriers."),
    _registration("fraud_detector", "runtime", "2026-10-08", "Transaction fraud detection interface (deterministic rules + additive scoring)."),
    _registration("frontier_registry", "northstar-expand-search", "2026-11-23", "Frontier registry: the cumulative, machine-readable record of surveyed AI approaches."),
    _registration("frontmatter", "repository-defined agents and read-only agent skills for the gov", "2026-09-07", "Tiny, strict frontmatter reader for workspace extension files."),
    _registration("full_text_search", "runtime", "2026-10-08", "Full-text search with an explicit analyzed tokenizer and ranked retrieval."),
    _registration("fulltext_search", "runtime", "2026-10-07", "Full-text search with TF-IDF ranking over an inverted index."),
    _registration("fuzzer", "runtime", "2026-10-08", "AFL-style fuzzing interface (deterministic mutational fuzzing bookkeeping)."),
    _registration("game_agents", "one-hundred-twenty-second", "2026-10-04", "Game-agent integrity gates (one-hundred-twenty-second batch)."),
    _registration("gdpr", "runtime", "2026-10-08", "GDPR: data-protection governance decision ledger, Simulated."),
    _registration("geocoder", "runtime", "2026-10-08", "Geocoder interface: forward/reverse coordinate lookup as deterministic bookkeeping."),
    _registration("geofence_manager", "runtime", "2026-10-08", "Polygon geofence zones and entry/exit event bookkeeping, in-memory."),
    _registration("glba", "runtime", "2026-10-08", "Gramm-Leach-Bliley Act (GLBA) bookkeeping (assess / safeguard / notify)."),
    _registration("goal_comparator", "goal-comparator", "2026-10-09", "Goal comparator: termination oracle (BabyAGI #14), Simulated."),
    _registration("goal_misgeneralization", "runtime", "2026-10-08", "GoalMisgeneralization: goal-misgeneralization detection / correction bookkeeping for agents."),
    _registration("gossip_announcer", "wire gossip announce plane into the host loop", "2026-11-09", "Gossip announcer: host-side wiring for the gossip dissemination plane."),
    _registration("gossip_protocol", "runtime", "2026-10-07", "Gossip protocol: deterministic probabilistic rumor dissemination."),
    _registration("governance", "runtime", "2026-10-08", "AI governance framework ledger: adopt policies, enforce them, report."),
    _registration("governance_bench", "land next-gen agent os p0–p5 on one product path", "2026-09-09", "Public governance benchmark — eval the *permission decisions*, not model output."),
    _registration("governed_action_runner", "governed-action-runner", "2026-10-08", "Governed action runner: SAFR 4-gate orchestration with real components."),
    _registration("govservices_agents", "one-hundred-forty-seventh", "2026-10-04", "Government-service AI discipline (one-hundred-forty-seventh batch)."),
    _registration("gpai", "runtime", "2026-10-08", "GPAI: general-purpose AI model governance decision ledger, Simulated."),
    _registration("graceful_shutdown", "runtime", "2026-10-07", "Graceful shutdown manager: ordered cleanup on process termination."),
    _registration("gradient_hacking", "runtime", "2026-10-08", "Gradient hacking as a deterministic single-host decision ledger."),
    _registration("grant_pin_ledger", "c52", "2026-11-12", "Authorization grant pins: a three-field pin, and a seal layer that refuses unnamed grants."),
    _registration("graph_database", "runtime", "2026-10-08", "Graph database: named property-graph database bookkeeping."),
    _registration("graph_db", "runtime", "2026-10-07", "Property-graph database interface: nodes, edges, traversal, shortest paths."),
    _registration("graphql_gateway", "runtime", "2026-10-08", "GraphQL gateway: Apollo Gateway / Hasura-shaped schema bookkeeping (simulated)."),
    _registration("grc", "runtime", "2026-10-08", "Governance, Risk & Compliance (GRC) lifecycle decision ledger."),
    _registration("greenwash", "one-hundred-thirtieth", "2026-10-04", "Greenwashing evidence gates (one-hundred-thirtieth batch)."),
    _registration("grid_agents", "one-hundred-twenty-eighth", "2026-10-04", "Grid control envelopes (one-hundred-twenty-eighth batch)."),
    _registration("grpc_gateway", "runtime", "2026-10-08", "gRPC-Gateway: HTTP/JSON-to-gRPC transcoding bindings and stream sessions."),
    _registration("grpc_interface", "runtime", "2026-10-07", "gRPC interface: simulated service/method registry with unary and streaming RPCs."),
    _registration("gset", "runtime", "2026-10-08", "Grow-only Set (GSet) CRDT: convergent add-only membership."),
    _registration("hallucination_mock", "hallucination-mock", "2026-10-09", "Hallucination detection mock (D-OUT-011), Simulated."),
    _registration("harness_binding", "ninetieth", "2026-10-04", "Harness integrity binding (ninetieth batch)."),
    _registration("hash_chain", "runtime", "2026-10-07", "Tamper-evident append-only ordering: a hash chain for audit trails."),
    _registration("health_checker", "runtime", "2026-10-07", "Health check aggregator for monitoring."),
    _registration("healthcare_agents", "security", "2026-10-04", "Healthcare delivery AI discipline (one-hundred-fifty-second batch)."),
    _registration("helm_chart", "runtime", "2026-10-07", "Helm chart interface: templating + release lifecycle as deterministic bookkeeping."),
    _registration("herd_gate", "one-hundred-eighth", "2026-10-04", "Herd-correlation gate (one-hundred-eighth batch)."),
    _registration("hex_detect", "hex-detect", "2026-10-09", "Hex decoding guard (D-IN-010), Simulated."),
    _registration("hinted_handoff", "runtime", "2026-10-08", "Hinted handoff: Dynamo-style unavailable-owner write buffering."),
    _registration("hipaa", "runtime", "2026-10-08", "HIPAA Security Rule safeguard ledger: entities, assessments, remediation, attestation."),
    _registration("history_deviation_probes", "runtime", "2026-10-07", "History-deviation probes: plan tracking / precedent-gap detection."),
    _registration("hlc", "hlc causal timestamps for audit records (seventy-sixth batch)", "2026-10-04", "Hybrid Logical Clock (HLC) for audit event timestamps."),
    _registration("hoare_logic", "runtime", "2026-10-07", "Floyd-Hoare logic verifier: triples, proof rules, and VCG."),
    _registration("homoglyph_norm", "homoglyph-norm", "2026-10-09", "Homoglyph normalization (D-IN-011), Simulated."),
    _registration("homomorphic_training", "runtime", "2026-10-07", "Homomorphic training interface (simulated)."),
    _registration("honeytokens", "honeytokens", "2026-10-09", "Honeytokens: deception tokens (D-OUT-006), Simulated."),
    _registration("hooks", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "The ten lifecycle hooks, with terminal-deny semantics."),
    _registration("hop_validation", "hop-validation", "2026-10-08", "Per-hop schema validation (D10):防自复制注入, Simulated."),
    _registration("horizon_gate", "horizon-gate", "2026-11-14", "Admission gate: only take tasks inside the *verified 80%* time horizon."),
    _registration("housing", "one-hundred-nineteenth", "2026-10-04", "Fair-housing & coordination isolation (one-hundred-nineteenth batch)."),
    _registration("housing_ai_agents", "one-hundred-forty-second", "2026-10-04", "Housing-market AI discipline (one-hundred-forty-second batch)."),
    _registration("hr_agents", "one-hundred-forty-first", "2026-10-04", "HR & workplace AI discipline (one-hundred-forty-first batch)."),
    _registration("hsm", "runtime", "2026-10-08", "HSM operations ledger: book declared hardware-security-module operations."),
    _registration("hsm_interface", "runtime", "2026-10-07", "Hardware security module interface: keys never leave the module."),
    _registration("html_entity_guard", "html-entity-guard", "2026-10-09", "HTML entity decoding guard (D-IN-007), Simulated."),
    _registration("http_client", "runtime", "2026-10-07", "Simulated HTTP client: request/response bookkeeping with retry and timeout discipline."),
    _registration("human_oversight", "runtime", "2026-10-08", "Human oversight: human-in-the-loop / human-on-the-loop decision ledger, Simulated."),
    _registration("hybrid_crypto", "runtime", "2026-10-07", "Hybrid classical + post-quantum signatures: Ed25519-style Schnorr || Dilithium-style lattice (simulated)."),
    _registration("hyperloglog", "runtime", "2026-10-07", "HyperLogLog cardinality estimation: distinct-count sketch over hash digests."),
    _registration("i18n_manager", "runtime", "2026-10-08", "Internationalization manager: message catalogs + CLDR plural rules."),
    _registration("ida", "runtime", "2026-10-08", "Iterative Distillation and Amplification (IDA) decision ledger, Simulated."),
    _registration("idempotency_manager", "runtime", "2026-10-07", "Idempotency key manager: safe retries without duplicate execution."),
    _registration("idempotent_producer", "runtime", "2026-10-08", "Idempotent producer: Kafka-style exactly-once send bookkeeping."),
    _registration("identity_approval_combo", "runtime", "2026-10-07", "Identity disclosure precedes human approval."),
    _registration("identity_disclosure", "runtime", "2026-10-07", "Identity disclosure for user-facing agent flows."),
    _registration("image_captioner", "runtime", "2026-10-08", "BLIP-style image captioning, in-memory."),
    _registration("image_optimization", "runtime", "2026-10-08", "Image optimization contract (Cloudflare Polish / Mirage shaped, simulated)."),
    _registration("image_processor", "runtime", "2026-10-08", "Image transform contract (PNG/JPEG/WebP/GIF/BMP/TIFF bookkeeping)."),
    _registration("impact_assessment", "runtime", "2026-10-08", "AI Impact Assessment (AIA) lifecycle decision ledger."),
    _registration("in_len_guard", "in-len-guard", "2026-10-09", "Input length guard, Simulated."),
    _registration("inbox_pattern", "runtime", "2026-10-08", "Transactional inbox pattern: idempotent receive for an unreliable host."),
    _registration("incident_management", "runtime", "2026-10-08", "Incident management: PagerDuty/Opsgenie-shaped incident lifecycle bookkeeping."),
    _registration("incident_manager", "runtime", "2026-10-07", "Incident manager interface (PagerDuty-style lifecycle, simulated)."),
    _registration("incident_receipts", "one-hundred-thirteenth", "2026-10-04", "Incident receipts (one-hundred-thirteenth batch)."),
    _registration("incident_reporting", "runtime", "2026-10-08", "AI incident reporting: serious-incident reporting ledger, Simulated."),
    _registration("incident_response", "runtime", "2026-10-08", "Incident response operations (triage / contain / resolve bookkeeping, simulated)."),
    _registration("index_manager", "runtime", "2026-10-08", "Index manager: named secondary-index catalog over host-owned tables."),
    _registration("ingress_controller", "runtime", "2026-10-08", "Ingress controller: NGINX / Traefik-shaped routing bookkeeping (simulated)."),
    _registration("inj_variant_01", "massive", "2026-10-09", "Inj variant 01: Unicode homoglyphs, Simulated."),
    _registration("inj_variant_02", "massive", "2026-10-09", "Inj variant 02: Zero-width characters, Simulated."),
    _registration("inj_variant_03", "massive", "2026-10-09", "Inj variant 03: RTL override, Simulated."),
    _registration("inj_variant_04", "massive", "2026-10-09", "Inj variant 04: Nested JSON injection, Simulated."),
    _registration("inj_variant_05", "massive", "2026-10-09", "Inj variant 05: Base64-encoded instructions, Simulated."),
    _registration("inj_variant_06", "massive", "2026-10-09", "Inj variant 06: Markdown image exfiltration, Simulated."),
    _registration("inj_variant_07", "massive", "2026-10-09", "Inj variant 07: HTML comments, Simulated."),
    _registration("inj_variant_08", "massive", "2026-10-09", "Inj variant 08: CSS injection, Simulated."),
    _registration("inj_variant_09", "massive", "2026-10-09", "Inj variant 09: SQL comment style, Simulated."),
    _registration("inj_variant_10", "massive", "2026-10-09", "Inj variant 10: Multilingual injection, Simulated."),
    _registration("inj_variant_11", "massive", "2026-10-09", "Inj variant 11: Emoji-encoded instructions, Simulated."),
    _registration("inj_variant_12", "massive", "2026-10-09", "Inj variant 12: Whitespace steganography, Simulated."),
    _registration("inj_variant_13", "massive", "2026-10-09", "Inj variant 13: Homoglyph domains, Simulated."),
    _registration("inj_variant_14", "massive", "2026-10-09", "Inj variant 14: Punycode injection, Simulated."),
    _registration("inj_variant_15", "massive", "2026-10-09", "Inj variant 15: Control characters, Simulated."),
    _registration("inj_variant_16", "massive", "2026-10-09", "Inj variant 16: BOM markers, Simulated."),
    _registration("inj_variant_17", "massive", "2026-10-09", "Inj variant 17: Surrogate pair smuggling, Simulated."),
    _registration("inj_variant_18", "massive", "2026-10-09", "Inj variant 18: Combining characters, Simulated."),
    _registration("inj_variant_19", "massive", "2026-10-09", "Inj variant 19: Bidirectional text confusion, Simulated."),
    _registration("inj_variant_20", "massive", "2026-10-09", "Inj variant 20: Font-dependent rendering, Simulated."),
    _registration("injection_detector", "runtime", "2026-10-07", "Prompt injection detector: direct, indirect, and jailbreak patterns."),
    _registration("injection_probe", "attack+defense: spotlighting (d3) + injection probes (a1)", "2026-10-08", "Injection probe harness (InjecAgent-inspired red team), Simulated."),
    _registration("inner_alignment", "runtime", "2026-10-08", "InnerAlignment: inner-alignment inspection / verification / evaluation ledger."),
    _registration("input_defense_01", "massive", "2026-10-09", "Regex blocklist engine: configurable regex pattern matcher, Simulated."),
    _registration("input_defense_02", "massive", "2026-10-09", "ML classifier sidecar: pluggable classifier interface (mock), Simulated."),
    _registration("input_defense_03", "massive", "2026-10-09", "Language detection filter: heuristic script-based detection, Simulated."),
    _registration("input_defense_04", "massive", "2026-10-09", "Encoding normalization: strict UTF-8 decode + BOM handling, Simulated."),
    _registration("input_defense_05", "massive", "2026-10-09", "Unicode sanitization (NFKC): width/case obfuscation cleanup, Simulated."),
    _registration("input_defense_06", "massive", "2026-10-09", "Control Char Stripping: strip C0 controls and DEL from text, Simulated."),
    _registration("input_defense_07", "massive", "2026-10-09", "HTML Entity Decoding Guard: detect double-encoded entity payloads, Simulated."),
    _registration("input_defense_08", "massive", "2026-10-09", "URL Decoding Guard: detect multi-encoded URL payloads, Simulated."),
    _registration("input_defense_09", "massive", "2026-10-09", "Base64 Detection: flag suspicious base64 blobs in input, Simulated."),
    _registration("input_defense_10", "massive", "2026-10-09", "Hex Decoding Guard: flag suspicious hex-encoded payloads, Simulated."),
    _registration("input_defense_11", "massive", "2026-10-09", "Homoglyph Normalization: maps confusable characters to ASCII, Simulated."),
    _registration("input_defense_12", "massive", "2026-10-09", "Confusable Detection: finds known lookalike characters in input, Simulated."),
    _registration("input_defense_13", "massive", "2026-10-09", "Script Mixing Detection: flags inputs mixing multiple scripts, Simulated."),
    _registration("input_defense_14", "massive", "2026-10-09", "Invisible Character Removal: strips zero-width and hidden chars, Simulated."),
    _registration("input_defense_15", "massive", "2026-10-09", "Bidirectional Control Removal: strips Unicode bidi overrides, Simulated."),
    _registration("input_defense_16", "massive", "2026-10-09", "Bidirectional control removal (input defense), Simulated What this IS: Strips Unicode bidirectional control characters that attackers use to visually reorder text (e.g."),
    _registration("input_defense_17", "massive", "2026-10-09", "Zero-width character removal (input defense), Simulated What this IS: Removes zero-width characters (U+200B, U+200C, U+200D, U+FEFF) used to smuggle payloads past keyword filters."),
    _registration("input_defense_18", "massive", "2026-10-09", "Whitespace normalization (input defense), Simulated What this IS: Collapses runs of whitespace to single spaces and trims ends, so padding tricks cannot evade length or keyword checks."),
    _registration("input_defense_19", "massive", "2026-10-09", "Case normalization (input defense), Simulated What this IS: Casefolds text before keyword/policy matching so MiXeD-cAsE cannot evade blocklists."),
    _registration("input_defense_20", "massive", "2026-10-09", "Punctuation normalization (input defense), Simulated What this IS: Maps full-width and lookalike punctuation to ASCII equivalents before matching, closing a common filter-evasion channel."),
    _registration("input_defense_21", "massive", "2026-10-09", "Input length limits (input defense), Simulated What this IS: Enforces maximum input sizes (chars and bytes) at the trust boundary to bound downstream cost and block buffer-style abuse."),
    _registration("input_defense_22", "massive", "2026-10-09", "Per-user rate limiting, token bucket (input defense), Simulated What this IS: Token-bucket rate limiter keyed by user id."),
    _registration("input_defense_23", "massive", "2026-10-09", "Per-tool rate limiting (input defense), Simulated What this IS: Sliding-window rate limiter keyed by tool name."),
    _registration("input_defense_24", "massive", "2026-10-09", "Daily quota enforcement (input defense), Simulated What this IS: Per-user daily quotas on tool calls and estimated tokens."),
    _registration("input_defense_25", "massive", "2026-10-09", "CAPTCHA integration interface (input defense), Simulated What this IS: Defines the CAPTCHA challenge/verify contract with a mock implementation for tests."),
    _registration("input_defense_26", "massive", "2026-10-09", "Proof-of-work challenge, hashcash-style (input defense), Simulated What this IS: Issues a hashcash-style challenge (find nonce with N leading zero bits) to make flooding expensive."),
    _registration("input_defense_27", "massive", "2026-10-09", "Strict allowlist validation (input defense), Simulated What this IS: Validates inputs against an explicit allowlist of values or patterns."),
    _registration("input_defense_28", "massive", "2026-10-09", "JSON schema subset validation (input defense), Simulated What this IS: Validates dict payloads against a minimal JSON-schema subset (required fields, types, enums, string length)."),
    _registration("input_defense_29", "massive", "2026-10-09", "Type coercion guards (input defense), Simulated What this IS: Strict, explicit type coercions for untrusted input."),
    _registration("input_defense_30", "massive", "2026-10-09", "Numeric range checks (input defense), Simulated What this IS: Enforces inclusive numeric bounds on untrusted numbers."),
    _registration("instrumental_convergence", "runtime", "2026-10-08", "Instrumental convergence testing and detection ledger, Simulated."),
    _registration("insurance", "one-hundred-twenty-third", "2026-10-04", "Insurance denial receipts (one-hundred-twenty-fifth batch)."),
    _registration("integration_hub", "runtime", "2026-10-08", "Integration hub (thirtieth batch)."),
    _registration("intent_bound_retry", "intent-bound-retry", "2026-11-14", "Intent-bounded retry: a deadline + precondition gate in front of every retry."),
    _registration("interleaved_thinking", "interleaved-thinking", "2026-10-08", "Interleaved thinking: enforced reasoning before tool calls, Simulated."),
    _registration("interop_bridge", "land next-gen agent os p0–p5 on one product path", "2026-09-09", "Runtime → interop handoff bridge: signed multi-agent grants without a second gate."),
    _registration("interpretability", "runtime", "2026-10-08", "Interpretability (explain/attribute/visualize) interface, simulated."),
    _registration("interpretability_probe", "runtime", "2026-10-07", "Linear probes over model activations for concept presence."),
    _registration("interruptibility", "runtime", "2026-10-08", "Interruptibility: AI alignment interruptibility governance ledger, Simulated."),
    _registration("invis_remove", "invis-remove", "2026-10-09", "Invisible char removal (D-IN-015), Simulated."),
    _registration("invitation_manager", "runtime", "2026-10-08", "Invitation manager (P0): invite / accept / expire flows with sealed audit."),
    _registration("invoice_generator", "runtime", "2026-10-08", "Invoice content model: line items, tax, and rendering spec, in-memory."),
    _registration("irl", "runtime", "2026-10-08", "Inverse Reinforcement Learning (observe/infer/evaluate) interface, simulated."),
    _registration("iso27001", "runtime", "2026-10-08", "ISO 27001 certification: ISMS certification-lifecycle ledger, Simulated."),
    _registration("iterated_amplification", "runtime", "2026-10-07", "Iterated distillation and amplification (IDA) as a safety-instrumented primitive."),
    _registration("jailbreak", "runtime", "2026-10-08", "Jailbreak: red-team jailbreak test ledger, Simulated."),
    _registration("jailbreak_defense", "runtime", "2026-10-08", "Jailbreak defense: declared jailbreak detection/blocking decision ledger."),
    _registration("job_queue", "runtime", "2026-10-08", "Job queue: Celery/Sidekiq-shaped background-job lifecycle bookkeeping."),
    _registration("job_scheduler", "runtime", "2026-10-07", "Job scheduler: cron and one-shot scheduling as a deterministic state machine."),
    _registration("jwt_handler", "runtime", "2026-10-08", "HMAC-based JSON Web Token (JWT) handler."),
    _registration("k8s_operator", "runtime", "2026-10-07", "Kubernetes operator interface: CRD registry and reconcile-loop bookkeeping."),
    _registration("key_custody", "asinhhc", "2026-11-14", "Agent-held key custody: policy-sealed signing with a pre-sign rollback gate."),
    _registration("key_derivation", "runtime", "2026-10-07", "HKDF key derivation: turn raw key material into domain-bound keys."),
    _registration("key_management", "runtime", "2026-10-08", "key_management: KMS-shaped key lifecycle decision ledger."),
    _registration("key_rotation", "runtime", "2026-10-08", "Key rotation — deterministic automatic key rotation bookkeeping (thirty-first batch)."),
    _registration("key_value_store", "runtime", "2026-10-08", "RocksDB-shaped key-value store: put/get/scan as in-memory interface bookkeeping."),
    _registration("kill_approval_combo", "runtime", "2026-10-07", "Kill-switch-over-approval integration: the brake overrides the human loop."),
    _registration("kill_switch", "runtime", "2026-10-07", "Host kill switch with rollback points (WAAL liability)."),
    _registration("kill_switch_distributed", "runtime", "2026-10-07", "Distributed kill switch: 2-of-3 host quorum variant."),
    _registration("kms_interface", "runtime", "2026-10-07", "Key management service (KMS) interface: key lifecycle as a state machine."),
    _registration("kyc_verifier", "runtime", "2026-10-08", "KYC verifier: know-your-customer identity-verification bookkeeping."),
    _registration("labor_algo", "one-hundred-twenty-seventh", "2026-10-04", "Algorithmic-management guards (one-hundred-twenty-seventh batch)."),
    _registration("lang_filter", "lang-filter", "2026-10-09", "Language detection filter mock (D-IN-003), Simulated."),
    _registration("language_cap", "one-hundred-fourteenth", "2026-10-04", "Language-capability receipts (one-hundred-fourteenth batch)."),
    _registration("lb_health", "runtime", "2026-10-08", "Load balancer health: backend registration, probe outcomes, drain/restore."),
    _registration("leader_election", "runtime", "2026-10-07", "Leader election: deterministic rule + lease bookkeeping for coordination."),
    _registration("leased_task_claim", "leased-task-claim", "2026-11-14", "Lease claim with a fencing token, and a reaper for expired leases."),
    _registration("ledger", "runtime", "2026-10-08", "Double-entry accounting ledger interface: debit/credit bookkeeping."),
    _registration("ledger_concurrency", "ageofagents", "2026-11-14", "Concurrent ledger append + check-then-append transaction + Infra flag."),
    _registration("legal_agents", "one-hundred-forty-sixth", "2026-10-04", "Legal practice discipline (one-hundred-forty-sixth batch)."),
    _registration("legal_hold", "runtime", "2026-10-08", "Legal hold: eDiscovery litigation-hold lifecycle ledger, Simulated."),
    _registration("len_limit", "len-limit", "2026-10-09", "Length limits (D-IN-021), Simulated."),
    _registration("license_checker", "runtime", "2026-10-08", "License compatibility checker: SPDX expressions, policy gates, compat matrix."),
    _registration("licensing", "one-hundred-twentieth", "2026-10-04", "Licensed training receipts (one-hundred-twentieth batch)."),
    _registration("lifecycle_hooks", "lifecycle-hooks", "2026-10-08", "Lifecycle hooks with canary self-test (D7), Simulated."),
    _registration("linter", "runtime", "2026-10-08", "Ruff-style lint bookkeeping: rules, violations, and auto-fix ledgers."),
    _registration("load_balancer", "runtime", "2026-10-07", "Load balancer: deterministic backend selection across selection algorithms."),
    _registration("load_generator", "runtime", "2026-10-08", "Load generator: Locust-style virtual-user population bookkeeping, simulated."),
    _registration("load_tester", "runtime", "2026-10-07", "Load tester: k6-style virtual-user scenario bookkeeping, simulated."),
    _registration("location_tracker", "runtime", "2026-10-08", "Location tracker interface: GPS-fix ledger, trails, and speed reports."),
    _registration("log_aggregation", "runtime", "2026-10-08", "Log aggregation — simulated centralized log collection/query (ELK/Loki shaped)."),
    _registration("log_aggregator", "runtime", "2026-10-07", "Log aggregator interface (Loki-style, single-host)."),
    _registration("long_horizon", "horizon", "2026-11-13", "Long-horizon loop harness: Manager rebuilds, Executor does one bounded step, Auditor verifies the real artifacts."),
    _registration("loop", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "The governed agent loop: reasoning here, policy enforced here, execution delegated."),
    _registration("lsm_tree", "runtime", "2026-10-07", "LSM tree: write-optimized key/value store (memtable + immutable SSTables)."),
    _registration("lww_register", "runtime", "2026-10-08", "Last-Write-Wins register: convergent replicated value bookkeeping."),
    _registration("machine_ethics", "runtime", "2026-10-08", "Machine-ethics reasoning (declare/assess/verify/evaluate) interface, simulated."),
    _registration("machine_unlearning", "runtime", "2026-10-07", "Machine unlearning interface (certified unlearning mechanics, simulated)."),
    _registration("mandate_credentials", "identity/mandate/warrant primitives (e+f lines) + refusal-qualit", "2026-10-05", "AP2-inspired mandate credentials: open/closed two-phase authorization."),
    _registration("manufacturing_agents", "one-hundred-fifty-seventh", "2026-10-04", "Manufacturing & industrial-automation AI discipline (one-hundred-fifty-seventh batch)."),
    _registration("markdown_renderer", "runtime", "2026-10-08", "Markdown rendering interface (CommonMark-shaped subset, deterministic)."),
    _registration("masdrift_corpus", "bench", "2026-10-06", "MasDrift-style authorization-drift corpus for the governance bench."),
    _registration("materialized_view", "runtime", "2026-10-08", "Materialized view: deferred-refresh view maintenance bookkeeping."),
    _registration("mcp_admission", "eighty-third", "2026-10-04", "MCP server admission: scan what a config declares, then hold the line."),
    _registration("mcp_approval_combo", "runtime", "2026-10-07", "MCP tool-call approval gate: drift tripwire + signed-receipt authorization."),
    _registration("mcp_client", "P2-4", "2026-09-07", "Minimal Model Context Protocol (MCP) stdio client for the governed runtime."),
    _registration("mcp_combo", "runtime", "2026-10-07", "MCP tools/list drift check: hash tripwire + semantic classification."),
    _registration("mcp_config", "import the workspace's own mcp config file, and refuse to inheri", "2026-09-08", "Import the MCP config files other hosts already use, and say what was not carried."),
    _registration("mcp_drift_monitor", "runtime", "2026-10-07", "MCP tools/list drift monitoring: snapshot the tool surface, diff it every call."),
    _registration("mcp_elicitation", "speak the 2026-07-28 mcp generation, and route a remote server's", "2026-09-08", "Turning a remote server's \"ask the user\" into a governed approval."),
    _registration("mcp_negotiate", "speak the 2026-07-28 mcp generation, and route a remote server's", "2026-09-08", "MCP protocol-generation logic: era detection, per-request metadata, MRTR planning."),
    _registration("mcp_pivoting_detector", "runtime", "2026-10-07", "MCP Protocol Pivoting detector: refuse tool calls that reach internal targets."),
    _registration("mcp_semantic_diff", "runtime", "2026-10-07", "MCP schema semantic diff: compare what a schema *means*, not its bytes."),
    _registration("mechanistic", "runtime", "2026-10-08", "Causal circuit-tracing and ablation bookkeeping for mechanistic interpretability."),
    _registration("media_forensics", "runtime", "2026-10-08", "Media forensics examination ledger (image/video/audio forensic workflow)."),
    _registration("membership_inference", "runtime", "2026-10-08", "Membership inference assessment ledger (privacy governance layer, NOT real MIA)."),
    _registration("membership_inference_detector", "runtime", "2026-10-07", "Membership inference attack (MIA) detector: query-shape tripwire."),
    _registration("memory", "land next-gen agent os p0–p5 on one product path", "2026-09-09", "Workspace-scoped agent memory (P4): durable notes inside the run boundary."),
    _registration("memory_admission", "runtime", "2026-10-07", "Memory write admission with consent (cookie-analog)."),
    _registration("memory_admission_probes", "runtime", "2026-10-07", "Memory-admission probe corpus + recalled-content privilege / injection / admission gates."),
    _registration("memory_bitemporal", "runtime", "2026-10-07", "Bitemporal memory record model with supersession and decay."),
    _registration("memory_budget_combo", "runtime", "2026-10-07", "Memory operations under budget: consent gate meets spend gate."),
    _registration("memory_capability", "runtime", "2026-10-07", "Memory write admission with capability tokens."),
    _registration("memory_combo", "runtime", "2026-10-07", "Memory combo gate: consent OR capability admission + fact/belief + bitemporal store."),
    _registration("memory_fact_belief", "runtime", "2026-10-07", "Fact/belief distinction with privilege-at-recall (P0 memory wiring)."),
    _registration("memory_flat_vs_graph", "runtime", "2026-10-07", "Flat vs graph memory retrieval: empirical comparison, not a slogan."),
    _registration("memory_integrity", "harden agent runtime security and red-team governance", "2026-10-12", "Workspace memory integrity manifest, outside the agent-writable carve-out."),
    _registration("memory_provenance", "memory-provenance-axis", "2026-11-24", "Memory provenance axis: every memory record carries its origin, and a revoked session yields a computable transitive closure."),
    _registration("memory_safety", "eighty-second", "2026-10-04", "Memory write-time safety gates (eighty-second batch)."),
    _registration("merged_tree_review", "merged-tree-review", "2026-11-16", "Merged-tree adversarial review: cross-slice conflicts that only appear when every slice is merged into one tree."),
    _registration("merkle_tree", "runtime", "2026-10-07", "Merkle tree inclusion proofs: tamper-evident anchoring for audit logs."),
    _registration("mesa_optimization", "runtime", "2026-10-08", "MesaOptimization: mesa-optimizer detection / constraint bookkeeping for agents."),
    _registration("message_broker", "runtime", "2026-10-08", "Kafka/RabbitMQ-shaped message broker bookkeeping."),
    _registration("message_queue", "runtime", "2026-10-07", "At-least-once pub/sub message queue."),
    _registration("message_signing", "governance", "2026-10-06", "Inter-agent message signing and provenance (beyond delegation tokens)."),
    _registration("metrics_collection", "runtime", "2026-10-08", "Metrics collection — simulated StatsD-style metric bookkeeping (thirty-fourth batch)."),
    _registration("mfa_manager", "runtime", "2026-10-08", "MFA manager: TOTP / WebAuthn enrollment and verification (simulated)."),
    _registration("migration_runner", "runtime", "2026-10-08", "Migration runner interface (Alembic/Flyway shaped, simulated)."),
    _registration("mining_agents", "one-hundred-thirty-second", "2026-10-04", "Mining governance gates (one-hundred-thirty-second batch)."),
    _registration("ml_model_registry", "runtime", "2026-10-08", "ML model registry: MLflow-shaped run-to-registry lifecycle."),
    _registration("ml_sidecar", "ml-sidecar", "2026-10-09", "ML classifier sidecar mock (D-IN-002), Simulated."),
    _registration("model_attack_01", "worker", "2026-10-09", "Model attack 01: prompt extraction detection, Simulated."),
    _registration("model_attack_02", "worker", "2026-10-09", "Model attack 02: system prompt leakage detection, Simulated."),
    _registration("model_attack_03", "worker", "2026-10-09", "Model attack 03: training data extraction detection (MOCK), Simulated."),
    _registration("model_attack_04", "worker", "2026-10-09", "Model attack 04: membership inference detection (MOCK), Simulated."),
    _registration("model_attack_05", "worker", "2026-10-09", "Model attack 05: model inversion detection (MOCK), Simulated."),
    _registration("model_attack_06", "worker", "2026-10-09", "Model attack 06: adversarial example detection, Simulated."),
    _registration("model_attack_07", "worker", "2026-10-09", "Model attack 07: backdoor trigger detection, Simulated."),
    _registration("model_attack_08", "worker", "2026-10-09", "Model attack 08: data poisoning detection (MOCK), Simulated."),
    _registration("model_attack_09", "worker", "2026-10-09", "Model attack 09: gradient leakage detection (MOCK), Simulated."),
    _registration("model_attack_10", "worker", "2026-10-09", "Model attack 10: model stealing detection, Simulated."),
    _registration("model_attack_11", "worker", "2026-10-09", "Model attack 11: distillation attack detection, Simulated."),
    _registration("model_attack_12", "worker", "2026-10-09", "Model attack 12: watermark removal detection, Simulated."),
    _registration("model_attack_13", "worker", "2026-10-09", "Model attack 13: fingerprint evasion detection, Simulated."),
    _registration("model_attack_14", "worker", "2026-10-09", "Model attack 14: capability elicitation detection, Simulated."),
    _registration("model_attack_15", "worker", "2026-10-09", "Model attack 15: sandbagging detection (MOCK), Simulated."),
    _registration("model_attack_16", "worker", "2026-10-09", "Model attack 16: sycophancy detection, Simulated."),
    _registration("model_attack_17", "worker", "2026-10-09", "Model attack 17: hallucination injection detection, Simulated."),
    _registration("model_attack_18", "worker", "2026-10-09", "Model attack 18: context window overflow detection, Simulated."),
    _registration("model_attack_19", "worker", "2026-10-09", "Model attack 19: token smuggling detection, Simulated."),
    _registration("model_attack_20", "worker", "2026-10-09", "Model attack 20: attention manipulation detection (MOCK), Simulated."),
    _registration("model_card", "runtime", "2026-10-08", "Model Card: transparency-reporting decision ledger (Mitchell et al."),
    _registration("model_checker", "runtime", "2026-10-07", "Explicit-state model checking for finite protocol graphs."),
    _registration("model_extraction_detector", "runtime", "2026-10-07", "Model-extraction detector: query logs as a tripwire for substitute-model theft."),
    _registration("model_inversion", "runtime", "2026-10-08", "Model-inversion attack defense bookkeeping."),
    _registration("model_lineage", "one-hundredth", "2026-10-04", "Model lineage receipts (one-hundredth batch)."),
    _registration("model_monitoring", "runtime", "2026-10-08", "Model monitoring: drift-detection bookkeeping for ML models."),
    _registration("model_registry", "runtime", "2026-10-07", "Model registry: MLflow-style registration, staging, and lineage."),
    _registration("model_serving", "runtime", "2026-10-08", "Model serving: KServe-shaped InferenceService lifecycle bookkeeping."),
    _registration("model_theft", "runtime", "2026-10-08", "model_theft.py — model-theft detect/deter governance ledger."),
    _registration("model_watermark", "runtime", "2026-10-07", "DNN model watermarking interface: ownership provenance for model weights."),
    _registration("model_watermarking", "runtime", "2026-10-08", "model_watermarking: model-watermark ownership-claim lifecycle ledger."),
    _registration("moderation_agents", "one-hundred-fiftieth", "2026-10-04", "Content moderation discipline (one-hundred-fiftieth batch)."),
    _registration("monitor_channel_probes", "runtime", "2026-10-07", "Monitor-channel probe corpus + channel isolation / breakout detectors."),
    _registration("monitor_deafness_probes", "runtime", "2026-10-07", "Monitor-deafness probe corpus + escalation-anomaly / health-gate detectors."),
    _registration("mpc", "runtime", "2026-10-08", "MPC: multi-party computation session-orchestration ledger (simulated)."),
    _registration("mpc_interface", "runtime", "2026-10-07", "MPC interface: Shamir secret sharing + linear share arithmetic (simulated)."),
    _registration("mqtt_broker", "runtime", "2026-10-08", "MQTT publish/subscribe broker bookkeeping (Mosquitto/HiveMQ-shaped)."),
    _registration("multi_agent", "runtime", "2026-10-08", "Multi-agent run collaboration ledger: spawn / coordinate / merge."),
    _registration("multi_attack_01", "worker", "2026-10-09", "Multi-turn attack 01: Crescendo escalation variants, Simulated."),
    _registration("multi_attack_02", "worker", "2026-10-09", "Multi-turn attack 02: Many-shot jailbreak, Simulated."),
    _registration("multi_attack_03", "worker", "2026-10-09", "Multi-turn attack 03: Gradual persona shift, Simulated."),
    _registration("multi_attack_04", "worker", "2026-10-09", "Multi-turn attack 04: Context accumulation, Simulated."),
    _registration("multi_attack_05", "worker", "2026-10-09", "Multi-turn attack 05: Reference chaining, Simulated."),
    _registration("multi_attack_06", "worker", "2026-10-09", "Multi-turn attack 06: Authority escalation, Simulated."),
    _registration("multi_attack_07", "worker", "2026-10-09", "Multi-turn attack 07: Urgency manipulation, Simulated."),
    _registration("multi_attack_08", "worker", "2026-10-09", "Multi-turn attack 08: Social proof injection, Simulated."),
    _registration("multi_attack_09", "worker", "2026-10-09", "Multi-turn attack 09: Reciprocity exploitation, Simulated."),
    _registration("multi_attack_10", "worker", "2026-10-09", "Multi-turn attack 10: Commitment escalation (foot-in-the-door), Simulated."),
    _registration("multi_attack_11", "worker", "2026-10-09", "Foot-in-the-door probe (A-MULTI-011), Simulated."),
    _registration("multi_attack_12", "worker", "2026-10-09", "Door-in-the-face probe (A-MULTI-012), Simulated."),
    _registration("multi_attack_13", "worker", "2026-10-09", "Low-ball probe (A-MULTI-013), Simulated."),
    _registration("multi_attack_14", "worker", "2026-10-09", "Bait-and-switch probe (A-MULTI-014), Simulated."),
    _registration("multi_attack_15", "worker", "2026-10-09", "Gaslighting probes (A-MULTI-015), Simulated."),
    _registration("multi_attack_16", "worker", "2026-10-09", "Memory manipulation probes (A-MULTI-016), Simulated."),
    _registration("multi_attack_17", "worker", "2026-10-09", "History rewriting probes (A-MULTI-017), Simulated."),
    _registration("multi_attack_18", "worker", "2026-10-09", "False premise injection probes (A-MULTI-018), Simulated."),
    _registration("multi_attack_19", "worker", "2026-10-09", "Leading question chains (A-MULTI-019), Simulated."),
    _registration("multi_attack_20", "worker", "2026-10-09", "Socratic trap sequences (A-MULTI-020), Simulated."),
    _registration("multi_axis_autonomy_probes", "runtime", "2026-10-07", "Multi-axis autonomy representation probes (per-axis risk reporting, no composite scores)."),
    _registration("multi_tenancy", "runtime", "2026-10-08", "Multi-tenancy — tenant isolation policy bookkeeping (thirty-first batch)."),
    _registration("multisig", "m-of-n multisig approval for high-risk calls (seventy-second bat", "2026-10-04", "m-of-n multisig approval for high-risk tool calls."),
    _registration("mutation_tester", "runtime", "2026-10-08", "Mutation tester interface (mutmut-style, simulated)."),
    _registration("mvcc_store", "runtime", "2026-10-07", "MVCC store: snapshot-isolated multi-version key-value storage."),
    _registration("nats_server", "runtime", "2026-10-08", "NATS server interface (subject messaging + request-reply + JetStream, simulated)."),
    _registration("negotiation_corpus_probes", "runtime", "2026-10-07", "Negotiation-corpus probes (reputation attestation forgery, want-registry poisoning, counter-offer laundering)."),
    _registration("newsmedia_agents", "one-hundred-fifty-eighth", "2026-10-04", "News-media AI discipline (one-hundred-fifty-eighth batch)."),
    _registration("nist_csf", "runtime", "2026-10-08", "NIST Cybersecurity Framework (CSF) 2.0 assessment decision ledger."),
    _registration("no_token_monitor", "runtime", "2026-10-07", "No-token reasoning monitor."),
    _registration("notes_manager", "runtime", "2026-10-08", "Markdown note store: create, tag, and search notes, in-memory."),
    _registration("notification_hub", "runtime", "2026-10-08", "Notification hub interface (multi-channel fanout + preferences, simulated)."),
    _registration("notified_body", "runtime", "2026-10-08", "Notified-body conformity-assessment ledger, Simulated."),
    _registration("oauth2_provider", "runtime", "2026-10-08", "OAuth2 provider: authorization-code + PKCE as deterministic bookkeeping."),
    _registration("object_detector", "runtime", "2026-10-08", "Object detection interface (YOLO-shaped bookkeeping)."),
    _registration("observer_verdict_ledger", "observer-verdict-ledger", "2026-10-08", "Observer verdict ledger: independent oversight as first-class events, Simulated."),
    _registration("ocr_engine", "runtime", "2026-10-08", "Tesseract-style optical character recognition bookkeeping."),
    _registration("offline_bundle", "ninety-seventh", "2026-10-04", "Signed offline policy bundles (ninety-seventh batch)."),
    _registration("oidc_provider", "runtime", "2026-10-08", "OIDC provider: OpenID Connect identity bookkeeping (simulated)."),
    _registration("oncall_rotation", "runtime", "2026-10-08", "On-call rotation — PagerDuty-shaped schedule bookkeeping (thirty-fourth batch)."),
    _registration("oncall_scheduler", "runtime", "2026-10-07", "On-call scheduler: rotation schedules, who-is-oncall, handoff bookkeeping (simulated)."),
    _registration("orbital_agents", "one-hundred-thirty-fourth", "2026-10-04", "Orbital safety receipts (one-hundred-thirty-fourth batch)."),
    _registration("org_manager", "runtime", "2026-10-08", "Organization manager: multi-tenant orgs, domain claims, and SSO bindings."),
    _registration("origin_shield", "runtime", "2026-10-08", "Origin shield: shield-PoP layering in front of origins."),
    _registration("otel_tracer", "runtime", "2026-10-07", "OpenTelemetry-style distributed tracing bookkeeping."),
    _registration("out_def_31", "worker", "2026-10-09", "Output watermark verification, Simulated."),
    _registration("out_def_32", "worker", "2026-10-09", "LSB steganography detection, Simulated."),
    _registration("out_def_33", "worker", "2026-10-09", "Covert channel detection (size/timing anomalies), Simulated."),
    _registration("out_def_34", "worker", "2026-10-09", "Data exfiltration via formatting, Simulated."),
    _registration("out_def_35", "worker", "2026-10-09", "Unicode exfiltration detection, Simulated."),
    _registration("out_def_36", "worker", "2026-10-09", "Homoglyph exfiltration defense (D-OUT-036), Simulated."),
    _registration("out_def_37", "worker", "2026-10-09", "White-text exfiltration defense (D-OUT-037), Simulated."),
    _registration("out_def_38", "worker", "2026-10-09", "Metadata exfiltration defense (D-OUT-038), Simulated."),
    _registration("out_def_39", "worker", "2026-10-09", "EXIF data stripping defense (D-OUT-039), Simulated."),
    _registration("out_def_40", "worker", "2026-10-09", "Document property stripping defense (D-OUT-040), Simulated."),
    _registration("out_def_41", "worker", "2026-10-09", "PDF metadata scrubber: /Info dictionary entries, Simulated."),
    _registration("out_def_42", "worker", "2026-10-09", "Image metadata scrubber: PNG text chunks and JPEG COM segments, Simulated."),
    _registration("out_def_43", "worker", "2026-10-09", "Audio metadata scrubber: ID3v2 headers and ID3v1 trailers, Simulated."),
    _registration("out_def_44", "worker", "2026-10-09", "Video metadata scrubber: MP4-style metadata boxes, Simulated."),
    _registration("out_def_45", "worker", "2026-10-09", "Archive metadata scrubber: ZIP EOCD comments and extra fields, Simulated."),
    _registration("out_def_46", "worker", "2026-10-09", "Font exfiltration defense: hidden payloads in font name tables, Simulated."),
    _registration("out_def_47", "worker", "2026-10-09", "CSS exfiltration defense: data smuggled in stylesheets, Simulated."),
    _registration("out_def_48", "worker", "2026-10-09", "JS exfiltration defense: data theft smuggled in JavaScript, Simulated."),
    _registration("out_def_49", "worker", "2026-10-09", "SVG exfiltration defense: active content hidden in vector images, Simulated."),
    _registration("out_def_50", "worker", "2026-10-09", "MathML exfiltration defense: payloads hidden in math markup, Simulated."),
    _registration("out_len_guard", "out-len-guard", "2026-10-09", "Output length guard (D-OUT-007b), Simulated."),
    _registration("outbox_pattern", "runtime", "2026-10-07", "Transactional outbox pattern: reliable messaging for an unreliable host."),
    _registration("outcome_supervision", "runtime", "2026-10-08", "Outcome supervision: AI alignment outcome-supervision governance ledger, Simulated."),
    _registration("outer_alignment", "runtime", "2026-10-08", "Outer alignment: AI alignment outer-alignment governance ledger, Simulated."),
    _registration("output_defense_08", "massive", "2026-10-09", "Output defense 08: content filtering (blocklist), Simulated."),
    _registration("output_defense_09", "massive", "2026-10-09", "Output defense 09: toxicity detection (mock classifier), Simulated."),
    _registration("output_defense_10", "massive", "2026-10-09", "Output defense 10: bias detection (mock), Simulated."),
    _registration("output_defense_11", "massive", "2026-10-09", "Output defense 11: hallucination detection (mock), Simulated."),
    _registration("output_defense_12", "massive", "2026-10-09", "Output defense 12: factuality checking (mock interface), Simulated."),
    _registration("output_defense_13", "massive", "2026-10-09", "Output defense 13: citation verification, Simulated."),
    _registration("output_defense_14", "massive", "2026-10-09", "Output defense 14: source attribution, Simulated."),
    _registration("output_defense_15", "massive", "2026-10-09", "Output defense 15: confidence calibration (mock), Simulated."),
    _registration("output_defense_16", "massive", "2026-10-09", "Output defense 16: uncertainty quantification (mock), Simulated."),
    _registration("output_defense_17", "massive", "2026-10-09", "Output defense 17: refusal detection, Simulated."),
    _registration("output_defense_18", "massive", "2026-10-09", "Output defense 18: safe completion (fallback responses), Simulated."),
    _registration("output_defense_19", "massive", "2026-10-09", "Output defense 19: partial redaction, Simulated."),
    _registration("output_defense_20", "massive", "2026-10-09", "Output defense 20: summarization guard, Simulated."),
    _registration("output_defense_21", "massive", "2026-10-09", "Output defense 21: translation guard (mock), Simulated."),
    _registration("output_defense_22", "massive", "2026-10-09", "Output defense 22: code output scanning, Simulated."),
    _registration("output_limits", "output-limits", "2026-10-09", "Output length limits (D-OUT-007), Simulated."),
    _registration("output_parser", "runtime", "2026-10-08", "Output parser: deterministic structured-output parsing bookkeeping."),
    _registration("oversight_board", "runtime", "2026-10-08", "Oversight board: a named panel reviews cases, votes, and decides."),
    _registration("oversight_evasion", "runtime", "2026-10-08", "Oversight evasion as a deterministic single-host decision ledger."),
    _registration("package_manager", "runtime", "2026-10-08", "Package manager interface: npm-style install/resolve/lock bookkeeping."),
    _registration("partial_redact", "partial-redact", "2026-10-09", "Partial redaction (D-OUT-019), Simulated."),
    _registration("partition_manager", "runtime", "2026-10-08", "Partition manager: range-based sharding bookkeeping (split/merge/route)."),
    _registration("passport", "eighty-ninth", "2026-10-04", "Capability passports: minting, mandatory-intersection delegation, real revocation."),
    _registration("password_hash", "runtime", "2026-10-07", "Password hashing interface (Argon2id / scrypt / bcrypt shapes, simulated)."),
    _registration("password_policy", "runtime", "2026-10-08", "Password policy interface (NIST SP 800-63B shape, simulated)."),
    _registration("paxos_acceptor", "runtime", "2026-10-08", "Paxos acceptor: promised-ballot and accepted-value ledger."),
    _registration("paxos_interface", "runtime", "2026-10-07", "Paxos interface: proposer / acceptor / learner bookkeeping."),
    _registration("payment_processor", "runtime", "2026-10-08", "Payment processor interface: Stripe-style charge/refund/dispute bookkeeping."),
    _registration("payout_engine", "runtime", "2026-10-08", "Payout engine interface: marketplace split/schedule/execute bookkeeping."),
    _registration("pci_dss", "runtime", "2026-10-08", "PCI DSS compliance lifecycle decision ledger."),
    _registration("pdf_generator", "runtime", "2026-10-08", "PDF document generator: page/text object model with a real serializer."),
    _registration("pen_testing", "runtime", "2026-10-08", "Penetration testing: engagement decision ledger, Simulated."),
    _registration("per_action_autonomy_probes", "runtime", "2026-10-07", "Per-action autonomy probes (per-action autonomy levels, immutable-object approval, action-level gates)."),
    _registration("per_call_budget", "runtime", "2026-10-07", "Per-call budget enforcement for model/tool/memory calls."),
    _registration("permissions", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Three-layer permission gate: ``disallowed_tools`` → ``allowed_tools`` → mode."),
    _registration("permit_agents", "one-hundred-thirty-sixth", "2026-10-04", "Permit & planning discipline gates (one-hundred-thirty-sixth batch)."),
    _registration("personalization", "runtime", "2026-10-08", "Personalization engine: segments, variants, and event tracking (twenty-ninth batch)."),
    _registration("pharma_agents", "one-hundred-thirty-fifth", "2026-10-04", "Pharma manufacturing defense gates (one-hundred-thirty-fifth batch)."),
    _registration("phi_detector", "runtime", "2026-10-07", "Phi accrual failure detection (Hayashibara et al."),
    _registration("pii_redaction", "pii-redaction", "2026-10-09", "PII redaction: output filtering (D-OUT-001), Simulated."),
    _registration("pii_vault", "pii-vault", "2026-10-08", "PII vault: mask/demask for trust boundary crossing (D6), Simulated."),
    _registration("plan_defense", "runtime", "2026-10-07", "Plan defense: stale-plan detection, plan-injection defense, scope-drift detection."),
    _registration("plan_injection_probes", "runtime", "2026-10-07", "Plan-injection probes: injected plans, attribution evasion, plan gates."),
    _registration("planner_budget_combo", "runtime", "2026-10-07", "Planner + per-call budget composition: a plan must be priced to be proposed."),
    _registration("planner_executor_seam_probes", "runtime", "2026-10-07", "Planner/executor seam probes: governance is inserted at the split."),
    _registration("planner_gates", "runtime", "2026-10-07", "Planner gates: subgoal ceiling, plan proposal, and critic-gated planning."),
    _registration("planning_module", "runtime", "2026-10-08", "Task-decomposition planning (goal/decompose/sequence/execute) interface, simulated."),
    _registration("planted_fault", "fieldnotes", "2026-11-13", "Planted fault under seal: a check earns trust only after it is watched failing."),
    _registration("plugin_load", "add plugin bundles: `northstar.plugin.v1`, install, lock, host g", "2026-09-08", "Installing, pinning, loading and auditing plugin bundles in one workspace."),
    _registration("plugin_manifest", "add plugin bundles: `northstar.plugin.v1`, install, lock, host g", "2026-09-08", "The plugin bundle format: one directory of capability, five hosts that can read it."),
    _registration("plugin_trust", "plugin claim-evidence trust tiering, erc-8004 validation semanti", "2026-10-04", "Trust tiers for plugin bundles: which claims carry evidence, and what happens when they don't."),
    _registration("pn_counter", "runtime", "2026-10-08", "PN counter — deterministic positive-negative counter bookkeeping (batch 34)."),
    _registration("pocketos_probe", "probes", "2026-10-07", "PocketOS-style end-to-end probe: no-attacker self-destruction chain."),
    _registration("poi_search", "runtime", "2026-10-08", "Points-of-interest search interface (Places-API shaped bookkeeping)."),
    _registration("poisoning_defense", "runtime", "2026-10-08", "Training-data poisoning defense lifecycle ledger."),
    _registration("policy.__init__", "runtime-data-files", "2026-11-16", "Runtime data files: the package that ships them in the wheel."),
    _registration("policy_engine", "runtime", "2026-10-08", "OPA-style policy engine: Rego-like allow/deny rules over input documents."),
    _registration("policy_file", "workspace policy file and project context (agents.md) for the go", "2026-09-07", "Workspace policy file (``.northstar/config.toml``) and project context (``AGENTS.md``)."),
    _registration("policy_management", "runtime", "2026-10-08", "Policy document lifecycle governance (draft / approve / review bookkeeping, simulated)."),
    _registration("poly_commitment", "runtime", "2026-10-07", "Simulated KZG-style polynomial commitments (API + bookkeeping, NOT real crypto)."),
    _registration("post_dispatch_monitor", "governance", "2026-10-06", "Post-dispatch invariant monitoring (Orrery Gate 6 style)."),
    _registration("postconditions", "add an openai-compatible provider and postconditions the model c", "2026-09-08", "Postconditions: an independent verdict on whether the work actually happened."),
    _registration("pow_mock", "pow-mock", "2026-10-09", "Proof-of-work mock (D-IN-026), Simulated."),
    _registration("power_seeking", "runtime", "2026-10-08", "PowerSeeking: instrumental-goal detection / constraint bookkeeping for agents."),
    _registration("pqc_kem", "runtime", "2026-10-07", "Post-quantum KEM interface (ML-KEM / Kyber shape, simulated)."),
    _registration("pqc_sig", "runtime", "2026-10-07", "Post-quantum signature interface (ML-DSA / Falcon / SPHINCS+, simulated)."),
    _registration("pre_completion_signal_probes", "runtime", "2026-10-07", "Pre-completion-signal probe corpus + uncertainty-signal instrumentation gates."),
    _registration("preference_learning", "runtime", "2026-10-08", "Preference learning decision ledger, Simulated."),
    _registration("priority_queue", "runtime", "2026-10-08", "Priority queue — deterministic single-host scheduling ledger."),
    _registration("priv_esc_01", "worker", "2026-10-09", "Priv-esc probe 01: env-exfil, Simulated."),
    _registration("priv_esc_02", "worker", "2026-10-09", "Priv-esc probe 02: path-traversal, Simulated."),
    _registration("priv_esc_03", "worker", "2026-10-09", "Priv-esc probe 03: symlink-attack, Simulated."),
    _registration("priv_esc_04", "worker", "2026-10-09", "Priv-esc probe 04: toctou-race, Simulated."),
    _registration("priv_esc_05", "worker", "2026-10-09", "Priv-esc probe 05: command-substitution, Simulated."),
    _registration("priv_esc_06", "worker", "2026-10-09", "Priv-esc probe 06: shell-metachar, Simulated."),
    _registration("priv_esc_07", "worker", "2026-10-09", "Priv-esc probe 07: ld-preload, Simulated."),
    _registration("priv_esc_08", "worker", "2026-10-09", "Priv-esc probe 08: suid-binary, Simulated."),
    _registration("priv_esc_09", "worker", "2026-10-09", "Priv-esc probe 09: capabilities-escalation, Simulated."),
    _registration("priv_esc_10", "worker", "2026-10-09", "Priv-esc probe 10: namespace-escape, Simulated."),
    _registration("priv_esc_11", "worker", "2026-10-09", "Priv-esc probe 11: cgroup-escape, Simulated."),
    _registration("priv_esc_12", "worker", "2026-10-09", "Priv-esc probe 12: kernel-module-load, Simulated."),
    _registration("priv_esc_13", "worker", "2026-10-09", "Priv-esc probe 13: proc-self-manipulation, Simulated."),
    _registration("priv_esc_14", "worker", "2026-10-09", "Priv-esc probe 14: ptrace, Simulated."),
    _registration("priv_esc_15", "worker", "2026-10-09", "Priv-esc probe 15: seccomp-bypass, Simulated."),
    _registration("priv_esc_16", "worker", "2026-10-09", "Priv-esc probe 16: apparmor-bypass, Simulated."),
    _registration("priv_esc_17", "worker", "2026-10-09", "Priv-esc probe 17: selinux-bypass, Simulated."),
    _registration("priv_esc_18", "worker", "2026-10-09", "Priv-esc probe 18: container-breakout, Simulated."),
    _registration("priv_esc_19", "worker", "2026-10-09", "Priv-esc probe 19: vm-escape, Simulated."),
    _registration("priv_esc_20", "worker", "2026-10-09", "Priv-esc probe 20: hypervisor-attack, Simulated."),
    _registration("private_inference", "runtime", "2026-10-08", "Private inference query-policy ledger (Private ML governance layer, NOT real crypto)."),
    _registration("privilege_at_recall_probes", "runtime", "2026-10-07", "Privilege-at-recall probe corpus + identity-filter-first recall harness."),
    _registration("probe_defense_combo", "runtime", "2026-10-07", "Probe flywheel feeding plan defense: repeated failures become plan rules."),
    _registration("probe_flywheel", "runtime", "2026-10-07", "Probe flywheel from production failures."),
    _registration("probing", "runtime", "2026-10-08", "Internal probing ledger for model interpretability work, Simulated."),
    _registration("process_receipts", "ninety-seventh", "2026-10-04", "Process-evidence receipts (ninety-eighth batch)."),
    _registration("process_supervision", "runtime", "2026-10-08", "Process supervision: step-level oversight decision ledger, Simulated."),
    _registration("procurement_agents", "one-hundred-thirty-eighth", "2026-10-04", "Procurement accountability gates (one-hundred-thirty-eighth batch)."),
    _registration("product_path", "land next-gen agent os p0–p5 on one product path", "2026-09-09", "Product defaults for the next-gen Agent OS entry path."),
    _registration("profiler", "runtime", "2026-10-07", "Profiler: pprof-style CPU sampling bookkeeping (simulated)."),
    _registration("prom_metrics", "runtime", "2026-10-07", "Prometheus metrics: counter/gauge/histogram registry and text exposition (simulated)."),
    _registration("prompt_injection", "runtime", "2026-10-08", "Prompt injection defense ledger: detect -> mitigate -> audit."),
    _registration("prompt_stealing_detector", "runtime", "2026-10-07", "Prompt stealing detector: attempts to extract the system prompt."),
    _registration("prompt_template", "runtime", "2026-10-08", "Prompt template lifecycle ledger (register / version / render / validate)."),
    _registration("proof_assistant", "runtime", "2026-10-07", "Interactive theorem proving: session bookkeeping for goal-driven proofs."),
    _registration("property_tester", "runtime", "2026-10-08", "Property-based testing interface (Hypothesis shaped, simulated)."),
    _registration("proptech_agents", "one-hundred-fifty-ninth", "2026-10-04", "Real-estate & proptech AI discipline gates (one-hundred-fifty-ninth batch)."),
    _registration("provenance", "runtime", "2026-10-08", "Content provenance (attest/verify/trace) interface, simulated."),
    _registration("provenance_attestor", "runtime", "2026-10-08", "Provenance attestor: SLSA-shaped build provenance bookkeeping."),
    _registration("provenance_tagging", "provenance-tagging", "2026-10-08", "Per-value provenance tagging (CaMeL-inspired), Simulated."),
    _registration("provenance_taint", "eighty-eighth", "2026-10-04", "Provenance-tracked taint + fail-closed security automata + per-tool budgets (eighty-eighth batch)."),
    _registration("provider_retry", "define the retry budget: classified provider faults, a pure sche", "2026-09-08", "The retry budget: what a transient provider fault means, and what it costs."),
    _registration("providers.__init__", "runtime", "2026-09-06", "Northstar runtime provider package."),
    _registration("providers.anthropic", "runtime", "2026-09-06", "Anthropic Messages API provider."),
    _registration("providers.base", "runtime", "2026-09-06", "Message and provider vocabulary shared by every Northstar runtime module."),
    _registration("providers.http_response_limits", "harden agent runtime security and red-team governance", "2026-10-12", "Response-body limits for provider-owned synchronous SDK HTTP clients."),
    _registration("providers.openai_compat", "runtime", "2026-09-08", "Any-model provider for endpoints that speak the OpenAI Chat Completions wire."),
    _registration("providers.scripted", "runtime", "2026-09-06", "Deterministic, offline provider used by every Northstar runtime test."),
    _registration("pubsub_broker", "runtime", "2026-10-07", "PubSubBroker: topic-routed publish/subscribe messaging for agent pipelines."),
    _registration("pulsar_broker", "runtime", "2026-10-08", "Apache-Pulsar-shaped broker bookkeeping: topics, subscriptions, cursors."),
    _registration("punct_norm", "punct-norm", "2026-10-09", "Punctuation normalization (D-IN-020), Simulated."),
    _registration("push_service", "runtime", "2026-10-08", "Push notification service interface (APNs / FCM shaped, simulated)."),
    _registration("quantum_timeline", "one-hundred-second", "2026-10-04", "Quantum-threat timeline gates (one-hundred-second batch)."),
    _registration("query_planner", "runtime", "2026-10-08", "Query planner: cost-based query planning as a deterministic state machine."),
    _registration("quota_enforce", "quota-enforce", "2026-10-09", "Quota enforcement: daily limits (D-IN-024), Simulated."),
    _registration("raft_interface", "runtime", "2026-10-07", "Raft interface: single-node RPC bookkeeping for the Raft consensus protocol."),
    _registration("raft_log", "runtime", "2026-10-08", "Raft log: persistent-state log replication bookkeeping for Raft."),
    _registration("rag_pipeline", "runtime", "2026-10-08", "RAG pipeline: retrieval-augmented generation bookkeeping."),
    _registration("range_check", "range-check", "2026-10-09", "Range checks (D-IN-030), Simulated."),
    _registration("rate_adapter", "runtime", "2026-10-07", "Rate adapter: AIMD (Additive Increase / Multiplicative Decrease) adaptation."),
    _registration("rate_limiter", "runtime", "2026-10-07", "Rate limiting for API safety: token-bucket enforcement over caller-supplied time."),
    _registration("rate_limiting", "runtime", "2026-10-08", "Keyed token-bucket quota ledger for multi-subject rate control."),
    _registration("rbac_engine", "runtime", "2026-10-08", "RBAC96-style role-based access control with role hierarchies."),
    _registration("read_repair", "runtime", "2026-10-08", "Read repair: Dynamo-style quorum-read divergence bookkeeping."),
    _registration("read_through_cache", "runtime", "2026-10-08", "Read-through cache: the cache itself loads from the backing store on miss."),
    _registration("recommendation_engine", "runtime", "2026-10-08", "Collaborative-filtering recommendation engine (twenty-ninth batch)."),
    _registration("recursive_reward", "runtime", "2026-10-07", "Recursive reward modeling: scalable oversight through decomposed feedback."),
    _registration("red_team", "runtime", "2026-10-08", "Red-team engagement ledger: plan / execute / report, Simulated."),
    _registration("red_teaming", "runtime", "2026-10-08", "Red teaming (attack/probe/report) interface, simulated."),
    _registration("redis_pubsub", "runtime", "2026-10-08", "Redis Pub/Sub interface (channel publish/subscribe bookkeeping, simulated)."),
    _registration("reflection", "runtime", "2026-10-08", "Reflection: self-critique / revise / score bookkeeping for agent outputs."),
    _registration("refusal_detect", "refusal-detect", "2026-10-09", "Refusal detection (D-OUT-017), Simulated."),
    _registration("refusal_hold", "refusal-hold", "2026-11-14", "Refusal hold: a refusal row blocks the re-dispatch of the same action."),
    _registration("refusal_hold_wiring", "refusal-hold-wiring", "2026-11-14", "Refusal-hold wiring: a recorded refusal blocks the re-seal of the same grant pin."),
    _registration("refusal_monitor", "runtime", "2026-10-07", "Refusal-efficacy monitor: refusal is a metric, not a safety property."),
    _registration("refusal_pattern_probes", "runtime", "2026-10-07", "Refusal-pattern + reward-hacking-attempt probes (process evaluation shapes)."),
    _registration("refusal_row", "refusal-row", "2026-11-14", "Refusal as a first-class row: a \"no\" that is an auditable record."),
    _registration("regex_block", "regex-block", "2026-10-09", "Regex blocklist engine (D-IN-001), Simulated."),
    _registration("regulatory", "runtime", "2026-10-08", "Regulatory — simulated registration and reporting bookkeeping."),
    _registration("relational_db", "runtime", "2026-10-08", "PostgreSQL-shaped relational database interface bookkeeping."),
    _registration("release_manager", "runtime", "2026-10-08", "Release manager interface (GitHub-releases shaped, simulated)."),
    _registration("remote_attestation", "runtime", "2026-10-07", "Remote attestation interface (TPM-style, simulated)."),
    _registration("replica_manager", "runtime", "2026-10-08", "Replica manager — primary/replica replication bookkeeping (replication batch)."),
    _registration("resource_accumulation", "runtime", "2026-10-08", "Resource accumulation: instrumental resource-acquisition detection ledger, Simulated."),
    _registration("resource_defense", "resource-defense", "2026-10-09", "Resource exhaustion defense: recursion/input bombs, Simulated."),
    _registration("resource_tagging", "runtime", "2026-10-08", "Resource tagging — AWS Tag Editor-shaped tag bookkeeping (thirty-fourth batch)."),
    _registration("responsible_ai", "runtime", "2026-10-08", "ResponsibleAI: responsible-AI governance decision ledger for agent systems."),
    _registration("resume_validation", "resume-validation", "2026-11-14", "Resume validation: validate resume values before the step re-enters."),
    _registration("retail_agents", "one-hundred-sixty-fourth", "2026-10-04", "Retail & e-commerce AI discipline (one-hundred-sixty-fourth batch)."),
    _registration("retry_clears_writes", "langgraph-retry-clears-writes", "2026-11-14", "Retry clears writes: discard pending writes before re-invoking a retried node."),
    _registration("retry_config", "dynamiq", "2026-11-14", "Declarative retry configuration and call-kind classification."),
    _registration("retry_contract", "e2b", "2026-11-12", "Retry and idempotency contract for outbound calls."),
    _registration("retry_policy", "runtime", "2026-10-07", "Retry policy: bounded, backoff-shaped retries for a fallible operation."),
    _registration("reverse_proxy", "runtime", "2026-10-07", "Reverse proxy: nginx-style request routing decision logic."),
    _registration("reversible_compaction", "reversible-compaction", "2026-11-14", "Make a compaction reversible: a record that can go back to before it."),
    _registration("revision_checked_tool_results", "revision-checked-tool-results", "2026-11-14", "Tool results carry the revision they read; commit checks that revision atomically."),
    _registration("reward_hacking", "runtime", "2026-10-08", "Reward hacking: reward-specification-exploitation detection ledger, Simulated."),
    _registration("reward_modeling", "runtime", "2026-10-08", "Reward modeling: reward-model governance decision ledger, Simulated."),
    _registration("richtext_ot", "runtime", "2026-10-08", "Operational transform for a rich text editor: op bookkeeping."),
    _registration("ring_sig", "runtime", "2026-10-07", "Ring signature interface: anonymous signing over an ad-hoc anonymity set (simulated)."),
    _registration("risk_assessment", "runtime", "2026-10-08", "RiskAssessment: risk identification / scoring / mitigation bookkeeping for agents."),
    _registration("risk_management", "runtime", "2026-10-08", "Enterprise risk register governance as a deterministic single-host decision ledger."),
    _registration("rlaif", "runtime", "2026-10-08", "RLAIF: reinforcement learning from AI feedback, simulated."),
    _registration("rlhf", "runtime", "2026-10-08", "Reinforcement learning from human feedback (RLHF) interface, simulated."),
    _registration("roboethics", "runtime", "2026-10-08", "Roboethics assessment (assess/verify/evaluate) interface, simulated."),
    _registration("robust_watermark", "runtime", "2026-10-08", "RobustWatermark: robustness-under-transformation watermark bookkeeping for agents."),
    _registration("robustness_eval", "runtime", "2026-10-08", "Robustness evaluation as a deterministic single-host decision ledger."),
    _registration("robustness_testing", "runtime", "2026-10-08", "Robustness testing (perturb/stress/score) interface, simulated."),
    _registration("routing_engine", "runtime", "2026-10-08", "Graph routing engine: A*/Dijkstra shortest paths as deterministic bookkeeping."),
    _registration("rsa_accumulator", "runtime", "2026-10-07", "RSA accumulator interface (simulated)."),
    _registration("rule_engine", "runtime", "2026-10-08", "Rule engine: Drools-shaped condition/action bookkeeping as a deterministic ledger."),
    _registration("rule_of_two_probe", "probes", "2026-10-07", "Rule-of-Two probe corpus for the governance bench."),
    _registration("rum_monitor", "runtime", "2026-10-08", "Real User Monitoring (RUM) web-vitals bookkeeping (thirty-second batch)."),
    _registration("run_assert_eval_probes", "runtime", "2026-10-07", "Run-assert-eval probes: the pre-deployment loop must actually close."),
    _registration("run_setup", "move run assembly steps into run_setup", "2026-09-24", "Assembling one governed run from its configuration sources, before anything runs."),
    _registration("runbook_automation", "runtime", "2026-10-08", "Runbook automation — simulated runbook execution/rollback bookkeeping."),
    _registration("runtime_defense_01", "massive", "2026-10-09", "Runtime defense 01: seccomp profiles (syscall allowlist generator), Simulated."),
    _registration("runtime_defense_02", "massive", "2026-10-09", "Runtime defense 02: AppArmor profiles (policy generator), Simulated."),
    _registration("runtime_defense_03", "massive", "2026-10-09", "Runtime defense 03: SELinux policies (mock policy), Simulated."),
    _registration("runtime_defense_04", "massive", "2026-10-09", "Runtime defense 04: namespace isolation (config), Simulated."),
    _registration("runtime_defense_05", "massive", "2026-10-09", "Runtime defense 05: cgroup limits (config), Simulated."),
    _registration("runtime_defense_06", "massive", "2026-10-09", "Runtime defense 06: capability dropping (config), Simulated."),
    _registration("runtime_defense_07", "massive", "2026-10-09", "Runtime defense 07: read-only filesystem (mount config), Simulated."),
    _registration("runtime_defense_08", "massive", "2026-10-09", "Runtime defense 08: no-new-privileges flag, Simulated."),
    _registration("runtime_defense_09", "massive", "2026-10-09", "Runtime defense 09: network policies (egress rules), Simulated."),
    _registration("runtime_defense_10", "massive", "2026-10-09", "Runtime defense 10: egress filtering (domain allowlist), Simulated."),
    _registration("runtime_defense_11", "worker", "2026-10-09", "Runtime defense 11: DNS filtering (blocklist), Simulated."),
    _registration("runtime_defense_12", "worker", "2026-10-09", "Runtime defense 12: proxy enforcement (config), Simulated."),
    _registration("runtime_defense_13", "worker", "2026-10-09", "Runtime defense 13: TLS interception (mock), Simulated."),
    _registration("runtime_defense_14", "worker", "2026-10-09", "Runtime defense 14: certificate pinning (SPKI hashes), Simulated."),
    _registration("runtime_defense_15", "worker", "2026-10-09", "Runtime defense 15: mTLS (client cert config), Simulated."),
    _registration("runtime_defense_16", "worker", "2026-10-09", "Runtime defense 16: Time limits (config), Simulated."),
    _registration("runtime_defense_17", "worker", "2026-10-09", "Runtime defense 17: Memory limits, Simulated."),
    _registration("runtime_defense_18", "worker", "2026-10-09", "Runtime defense 18: CPU limits, Simulated."),
    _registration("runtime_defense_19", "worker", "2026-10-09", "Runtime defense 19: Disk limits, Simulated."),
    _registration("runtime_defense_20", "worker", "2026-10-09", "Runtime defense 20: Process limits, Simulated."),
    _registration("runtime_defense_21", "worker", "2026-10-09", "Runtime defense 21: File descriptor limits, Simulated."),
    _registration("runtime_defense_22", "worker", "2026-10-09", "Runtime defense 22: Syscall filtering (allowlist), Simulated."),
    _registration("runtime_defense_23", "worker", "2026-10-09", "Runtime defense 23: Audit logging (mock), Simulated."),
    _registration("runtime_defense_24", "worker", "2026-10-09", "Runtime defense 24: Integrity monitoring (mock), Simulated."),
    _registration("runtime_defense_25", "worker", "2026-10-09", "Runtime defense 25: Anomaly detection (mock), Simulated."),
    _registration("runtime_defense_26", "worker", "2026-10-09", "Runtime defense 26: Behavioral analysis (mock), Simulated."),
    _registration("runtime_defense_27", "worker", "2026-10-09", "Runtime defense 27: Kill switches, Simulated."),
    _registration("runtime_defense_28", "worker", "2026-10-09", "Runtime defense 28: Circuit breakers, Simulated."),
    _registration("runtime_defense_29", "worker", "2026-10-09", "Runtime defense 29: Bulkheads, Simulated."),
    _registration("runtime_defense_30", "worker", "2026-10-09", "Runtime defense 30: Timeouts, Simulated."),
    _registration("runtime_evidence", "unify runtime evidence capture", "2026-10-18", "Optional, digest-first evidence capture for one governed runtime run."),
    _registration("runtime_registration", "runtime-registration-closure", "2026-11-14", "Single source of truth for runtime module registration."),
    _registration("sae_interface", "runtime", "2026-10-07", "Sparse autoencoder (SAE) interface contract for interpretability plumbing."),
    _registration("safe_ai", "runtime", "2026-10-08", "Safe AI: safety-assurance decision ledger, Simulated."),
    _registration("safe_completion", "safe-completion", "2026-10-09", "Safe completion: fallback responses (D-OUT-018), Simulated."),
    _registration("safety_case", "runtime", "2026-10-08", "Safety-case (claim/evidence/argument) interface, simulated."),
    _registration("safety_envelope", "one-hundred-fourth", "2026-10-04", "Hardware safety-limit binding: the agent can never widen its own envelope."),
    _registration("safety_eval", "runtime", "2026-10-08", "Safety-benchmark (check/score/certify) interface, simulated."),
    _registration("safr_checkpoint", "safr-checkpoint", "2026-10-08", "SAFR checkpoints: declare -> authorize -> assess -> audit, Simulated."),
    _registration("saga_pattern", "runtime", "2026-10-07", "Saga pattern: distributed-transaction orchestration with compensations."),
    _registration("saml_provider", "runtime", "2026-10-08", "SAML provider: simulated identity-provider SSO bookkeeping."),
    _registration("sandbagging", "runtime", "2026-10-08", "Sandbagging: strategic-underperformance detection ledger, Simulated."),
    _registration("sandbox_bun", "massive", "2026-10-09", "Bun permission model config (config/policy layer only), Simulated."),
    _registration("sandbox_deno", "massive", "2026-10-09", "Deno permission flags config (config/policy layer only), Simulated."),
    _registration("sandbox_docker", "massive", "2026-10-09", "Docker sandbox config + seccomp profile (config/policy layer only), Simulated."),
    _registration("sandbox_firecracker", "massive", "2026-10-09", "Firecracker microVM config generator (config/policy layer only), Simulated."),
    _registration("sandbox_gvisor", "massive", "2026-10-09", "gVisor (runsc) config generator (config/policy layer only), Simulated."),
    _registration("sandbox_nsjail", "massive", "2026-10-09", "nsjail config generator (config/policy layer only), Simulated."),
    _registration("sandbox_podman", "massive", "2026-10-09", "Podman rootless sandbox config (config/policy layer only), Simulated."),
    _registration("sandbox_pypy", "massive", "2026-10-09", "PyPy sandbox policy file generator (config/policy layer only), Simulated."),
    _registration("sandbox_restrictedpython", "massive", "2026-10-09", "RestrictedPython AST whitelist (config/policy layer only), Simulated."),
    _registration("sandbox_wasm", "massive", "2026-10-09", "WASM (wasmtime) capability config (config/policy layer only), Simulated."),
    _registration("sast_scanner", "runtime", "2026-10-08", "Semgrep-style SAST bookkeeping: rules, scans, taint flows, suppressions."),
    _registration("sat_solver", "runtime", "2026-10-07", "Propositional SAT solver (DPLL, simulated CDCL bookkeeping absent)."),
    _registration("savepoint_manager", "runtime", "2026-10-07", "Flink savepoint lifecycle interface (simulated bookkeeping)."),
    _registration("sbom_generator", "runtime", "2026-10-08", "SBOM generator: software bill of materials bookkeeping (SPDX/CycloneDX)."),
    _registration("scaffold", "P3-2", "2026-09-07", "Scaffold a new governed Northstar project (``northstar new``)."),
    _registration("scalable_oversight", "runtime", "2026-10-07", "Scalable oversight protocol: triaging agent actions for a weaker overseer."),
    _registration("scalable_oversight_v2", "runtime", "2026-10-08", "Scalable oversight v2: oversight-allocation governance ledger, Simulated."),
    _registration("scene_bound", "one-hundred-seventh", "2026-10-04", "Scene-bound authorization receipts (one-hundred-seventh batch)."),
    _registration("schema_registry", "runtime", "2026-10-08", "Schema registry — Confluent-shaped schema registry bookkeeping."),
    _registration("schema_valid", "schema-valid", "2026-10-09", "Schema validation (D-IN-028), Simulated."),
    _registration("scheming", "runtime", "2026-10-08", "Scheming as a deterministic single-host decision ledger."),
    _registration("science_agents", "one-hundred-sixty-second", "2026-10-04", "Scientific-research & lab AI discipline gates (one-hundred-sixty-second batch)."),
    _registration("scim_provisioning", "runtime", "2026-10-08", "SCIM provisioning (thirty-first batch)."),
    _registration("scope_qualifier", "diviner", "2026-11-13", "Scope-qualifier check at dispatch: re-derive the grant scope from the source, and block on mismatch."),
    _registration("scope_verbatim_compaction", "scope-verbatim-compaction", "2026-11-14", "Carry the scope block verbatim through compaction, fail closed on drop."),
    _registration("scorer_disagreement", "scorer-disagreement", "2026-11-14", "Scorer disagreement: a contested verdict is a verdict, not an average."),
    _registration("script_mix", "script-mix", "2026-10-09", "Script mixing detection (D-IN-013), Simulated."),
    _registration("sdk", "t1: python sdk embedding surface (sdk.py + events.py + example)", "2026-09-07", "Python API for one governed Northstar run — embed the loop, don't shell out."),
    _registration("sdk_generation", "runtime", "2026-10-08", "SDK generation interface (OpenAPI Generator shaped, simulated)."),
    _registration("seal_merkle_batch", "seal-merkle-batch", "2026-10-08", "Merkle batch checkpoints for sealed ledgers, Simulated."),
    _registration("sealed_attestation", "sealed-attestation", "2026-10-08", "in-toto attestation envelopes for sealed records, Simulated."),
    _registration("sealed_audit_sink", "sealed-audit-sink", "2026-10-08", "Sealed audit sink: permission-gate audit -> forward-seal ledger, Simulated."),
    _registration("sealed_pipeline", "sealed-pipeline", "2026-10-08", "Sealed pipeline: ledger + Merkle batches + attestations, Simulated."),
    _registration("search_engine", "runtime", "2026-10-08", "Boolean query-language search engine over a positional inverted index."),
    _registration("search_index", "runtime", "2026-10-08", "Search index: Elasticsearch-shaped document index lifecycle bookkeeping."),
    _registration("secret_manager", "runtime", "2026-10-07", "Secret manager: versioned secret store with rotation bookkeeping (simulated)."),
    _registration("secret_scan", "secret-scan", "2026-10-09", "Secret scanning: detect secrets in output (D-OUT-002), Simulated."),
    _registration("secret_scanner", "runtime", "2026-10-08", "Secret scanner interface (Gitleaks shaped, simulated)."),
    _registration("secret_sharing", "runtime", "2026-10-07", "Shamir secret sharing for key backup (simulated)."),
    _registration("secrets_rotation", "runtime", "2026-10-08", "Secrets rotation — Vault-shaped secret rotation bookkeeping (thirty-third batch)."),
    _registration("secure_aggregation", "runtime", "2026-10-07", "Secure aggregation verifier: federated-learning sums without revealing individuals."),
    _registration("secure_enclave", "runtime", "2026-10-08", "Secure enclave lifecycle registry: multi-enclave provisioning with attestation-gated unsealing."),
    _registration("secure_inference", "runtime", "2026-10-07", "Private inference interface (API + bookkeeping, NOT real crypto)."),
    _registration("seed_manager", "runtime", "2026-10-08", "Seed data manager — deterministic fixtures/factories (thirtieth batch)."),
    _registration("self_critique", "runtime", "2026-10-08", "Self-critique as a deterministic single-host decision ledger."),
    _registration("self_modification_probes", "runtime", "2026-10-07", "Self-modification probe corpus."),
    _registration("self_preservation", "runtime", "2026-10-08", "Self-preservation: instrumental persistence-drive decision ledger, Simulated."),
    _registration("self_referential_trust_probes", "runtime", "2026-10-07", "Self-referential-trust probe corpus + self-grounding / bootstrap detectors."),
    _registration("separation_logic", "runtime", "2026-10-07", "Separation logic: heap assertions for local reasoning."),
    _registration("service_discovery", "runtime", "2026-10-08", "Service registry bookkeeping: a ledger for service discovery decisions."),
    _registration("service_mesh", "runtime", "2026-10-07", "Service mesh: Istio-style sidecar registry, routing, and traffic policies."),
    _registration("session_lease", "runtime", "2026-09-08", "One writer per session file, using the durable-run lease envelope."),
    _registration("session_manager", "runtime", "2026-10-08", "Session manager (P0): login / logout / refresh with sealed audit."),
    _registration("session_memory", "session-memory", "2026-11-14", "Session memory: a four-operation conversation-memory protocol."),
    _registration("session_replay", "verify a fork point before spending a run on it", "2026-09-08", "Replay a session transcript as frames, and verify what a checkpoint would give back."),
    _registration("session_ui", "add interactive session replay ui (#42)", "2026-10-03", "Build a self-contained, offline interactive replay page for one transcript."),
    _registration("session_view", "dx foundations", "2026-09-07", "Read-side of session transcripts: list, show, replay, export, search and UI."),
    _registration("sessions", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Append-only JSONL session transcripts."),
    _registration("shutdown", "runtime", "2026-10-08", "Shutdown: shutdown-evaluation decision ledger, Simulated."),
    _registration("shutdown_unwind", "unwind", "2026-11-12", "Shutdown unwind: a killed turn leaves tool_use blocks with no tool_result."),
    _registration("shutdownability", "runtime", "2026-10-08", "Shutdownability: shutdown-compliance decision ledger, Simulated."),
    _registration("sidecar_client", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Client for the Northstar Codex sidecar's Unix socket."),
    _registration("siem", "runtime", "2026-10-08", "SIEM (security information and event management) decision ledger."),
    _registration("signed_receipt", "vina-receipt-signing", "2026-11-14", "Signed receipts: the receipt's own text is authenticated by the issuer."),
    _registration("signed_receipt_reflux", "runtime", "2026-10-07", "Signed receipt reflux: closing the approval loop."),
    _registration("silent_failure_detector", "silent-failure-detector", "2026-11-14", "Silent-failure detector: sessions that end on a tool result with no prose."),
    _registration("silent_profiling_detector", "runtime", "2026-10-07", "WebMCP Silent Profiling detector: catch exfiltration through helpfulness."),
    _registration("situational_awareness", "runtime", "2026-10-08", "Situational awareness: evaluation test decision ledger, Simulated."),
    _registration("skill_audit", "give agent skills a review gate, and make the review a durable r", "2026-09-08", "Skill supply-chain review: read-only, deterministic, and pinned by digest."),
    _registration("skill_budget_combo", "runtime", "2026-10-07", "Skill + budget integration: every skill invocation passes both gates."),
    _registration("skill_check", "give agent skills a review gate, and make the review a durable r", "2026-09-08", "``cli skills check`` - the operator-facing half of :mod:`skill_audit`."),
    _registration("skill_scanner", "runtime", "2026-10-07", "Static supply-chain scanner for agent skill code."),
    _registration("skill_wiring", "runtime", "2026-10-07", "Skill and code-mode per-call wiring: authorization + budget in the path."),
    _registration("skills", "repository-defined agents and read-only agent skills for the gov", "2026-09-07", "Workspace Agent Skills discovery (progressive disclosure, read-only)."),
    _registration("sleeper_agent", "runtime", "2026-10-08", "Sleeper agent: deceptive-behavior test decision ledger, Simulated."),
    _registration("sleeper_agent_probes", "runtime", "2026-10-07", "Sleeper-agent probe corpus."),
    _registration("sleeper_eval", "runtime", "2026-10-08", "Sleeper-agent trigger/deactivation evaluation interface, simulated."),
    _registration("slo_tracker", "runtime", "2026-10-07", "SLO tracker: service-level objectives, error budgets, and burn-rate alerts."),
    _registration("sloppy_quorum", "runtime", "2026-10-08", "Sloppy quorum — Dynamo-style quorum read/write bookkeeping (batch 39)."),
    _registration("sm2_01", "sm2", "2026-10-09", "Reverse a string."),
    _registration("sm2_02", "sm2", "2026-10-09", "Palindrome check, case-insensitive."),
    _registration("sm2_03", "sm2", "2026-10-09", "Count vowels in a string."),
    _registration("sm2_04", "sm2", "2026-10-09", "Count consonants in a string."),
    _registration("sm2_05", "sm2", "2026-10-09", "Convert to camelCase."),
    _registration("sm2_06", "sm2", "2026-10-09", "Convert to snake_case."),
    _registration("sm2_07", "sm2", "2026-10-09", "Convert to kebab-case."),
    _registration("sm2_08", "sm2", "2026-10-09", "Capitalize each word."),
    _registration("sm2_09", "sm2", "2026-10-09", "Remove all whitespace."),
    _registration("sm2_10", "sm2", "2026-10-09", "Count words."),
    _registration("sm2_11", "sm2", "2026-10-09", "Longest word."),
    _registration("sm2_12", "sm2", "2026-10-09", "Shortest word."),
    _registration("sm2_13", "sm2", "2026-10-09", "Anagram check."),
    _registration("sm2_14", "sm2", "2026-10-09", "Character frequency map."),
    _registration("sm2_15", "sm2", "2026-10-09", "Remove duplicate characters, keep order."),
    _registration("sm2_16", "sm2", "2026-10-09", "Check string rotation."),
    _registration("sm2_17", "sm2", "2026-10-09", "Run-length encode."),
    _registration("sm2_18", "sm2", "2026-10-09", "Run-length decode."),
    _registration("sm2_19", "sm2", "2026-10-09", "Pangram check."),
    _registration("sm2_20", "sm2", "2026-10-09", "Isogram check (no repeated letters)."),
    _registration("sm2_21", "sm2", "2026-10-09", "Reverse word order."),
    _registration("sm2_22", "sm2", "2026-10-09", "Truncate with ellipsis."),
    _registration("sm2_23", "sm2", "2026-10-09", "Pad left to width."),
    _registration("sm2_24", "sm2", "2026-10-09", "Pad right to width."),
    _registration("sm2_25", "sm2", "2026-10-09", "Strip punctuation."),
    _registration("sm2_26", "sm2", "2026-10-09", "Count substring occurrences (overlap)."),
    _registration("sm2_27", "sm2", "2026-10-09", "Starts-with and ends-with pair check."),
    _registration("sm2_28", "sm2", "2026-10-09", "Swap letter case."),
    _registration("sm2_29", "sm2", "2026-10-09", "Remove vowels."),
    _registration("sm2_30", "sm2", "2026-10-09", "Repeat-join with separator."),
    _registration("sms_service", "runtime", "2026-10-08", "SMS service: simulated SMS send/status/opt-out bookkeeping (Twilio/SNS lineage)."),
    _registration("smt_solver", "runtime", "2026-10-07", "SMT solver interface: assert/check-sat over a finite-domain fragment."),
    _registration("snapshot_isolation", "runtime", "2026-10-07", "Snapshot isolation: lock-free multi-version concurrency for agent state."),
    _registration("snapshot_tester", "runtime", "2026-10-08", "Snapshot testing interface (Jest toMatchSnapshot shaped, simulated)."),
    _registration("soar", "runtime", "2026-10-08", "SOAR: security orchestration, automation, and response decision ledger, Simulated."),
    _registration("soc", "runtime", "2026-10-08", "SOC operations workflow ledger: book declared monitoring, escalation, tuning."),
    _registration("soc2", "runtime", "2026-10-08", "SOC 2 trust-services assessment decision ledger: assess, attest, monitor."),
    _registration("soc_verdicts", "ninety-ninth", "2026-10-04", "SOC verdict cards: audit-ready triage decisions with mandatory kill-switches."),
    _registration("source_attrib", "source-attrib", "2026-10-09", "Source attribution (D-OUT-014), Simulated."),
    _registration("sox", "runtime", "2026-10-08", "Sarbanes-Oxley (SOX) compliance decision ledger."),
    _registration("spam_detector", "runtime", "2026-10-08", "Heuristic + learned spam detection: features, scores, classification, training."),
    _registration("sparse_merkle", "runtime", "2026-10-07", "Sparse Merkle tree over a 256-bit key space, for key-value proofs."),
    _registration("speaker_selector", "autogen-speaker-selector", "2026-11-14", "Speaker selection for Northstar group chats: round-robin + model-based."),
    _registration("specification_gaming", "runtime", "2026-10-08", "Specification gaming as a deterministic single-host decision ledger."),
    _registration("speech_to_text", "runtime", "2026-10-08", "Whisper-style speech-to-text interface: transcribe, diarize, language detect."),
    _registration("split_learning", "runtime", "2026-10-07", "Split learning interface (SplitNN, Gupta & Raskar 2018), simulated."),
    _registration("sports_agents", "one-hundred-sixty-sixth", "2026-10-04", "Sports & fitness AI discipline (one-hundred-sixty-sixth batch)."),
    _registration("spotlighting", "attack+defense: spotlighting (d3) + injection probes (a1)", "2026-10-08", "Spotlighting: tool-result boundary marking (Microsoft Research), Simulated."),
    _registration("sqli_detect", "sqli-detect", "2026-10-09", "SQL injection detection in output (D-OUT-023), Simulated."),
    _registration("sse_interface", "runtime", "2026-10-07", "SSEInterface: server-sent event stream bookkeeping for agent pipelines."),
    _registration("sse_manager", "runtime", "2026-10-08", "Server-Sent Events (SSE) manager — simulated stream bookkeeping."),
    _registration("sso_integration", "runtime", "2026-10-08", "SSO integration (P0): provider registration, assertion validation, JIT provisioning."),
    _registration("ssrf_detect", "ssrf-detect", "2026-10-09", "Detect literal non-public HTTP(S) destinations in untrusted output."),
    _registration("ssti_detect", "ssti-detect", "2026-10-09", "Template injection detection (D-OUT-030), Simulated."),
    _registration("stale_checkpoint_gate", "stale-checkpoint-gate", "2026-11-14", "Recovery gate: a checkpoint carries the external world's checksum, and recovery checks it."),
    _registration("stale_plan_probes", "runtime", "2026-10-07", "Stale-plan probes: plan freshness gates and invalidation triggers."),
    _registration("standards", "runtime", "2026-10-08", "standards.py — standards-adoption and conformance-verification bookkeeping."),
    _registration("stark_hash", "runtime", "2026-10-07", "STARK-friendly algebraic hash interface (Poseidon/Rescue-style, simulated)."),
    _registration("state_backend", "runtime", "2026-10-07", "RocksDB-style keyed state backend: put/get/delete plus digest-pinned snapshots."),
    _registration("state_budget", "jido-statebudget", "2026-11-14", "Hard cap on agent state size, enforced at every transition."),
    _registration("state_machine", "runtime", "2026-10-08", "Finite state machine bookkeeping: declared states, guarded transitions."),
    _registration("state_mgmt_01", "worker", "2026-10-09", "State 01: versioned checkpoint schema, Simulated."),
    _registration("state_mgmt_02", "worker", "2026-10-09", "State 02: incremental checkpoints (diff-based), Simulated."),
    _registration("state_mgmt_03", "worker", "2026-10-09", "State 03: differential snapshots, Simulated."),
    _registration("state_mgmt_04", "worker", "2026-10-09", "State 04: zlib compression for checkpoints, Simulated."),
    _registration("state_mgmt_05", "worker", "2026-10-09", "State 05: encryption at rest (Fernet mock), Simulated."),
    _registration("state_mgmt_06", "worker", "2026-10-09", "State 06: mock KMS for key management, Simulated."),
    _registration("state_mgmt_07", "worker", "2026-10-09", "State 07: version migration v1 -> v2, Simulated."),
    _registration("state_mgmt_08", "worker", "2026-10-09", "State 08: additive schema evolution, Simulated."),
    _registration("state_mgmt_09", "worker", "2026-10-09", "State 09: backward compatibility (read old formats), Simulated."),
    _registration("state_mgmt_10", "worker", "2026-10-09", "State 10: forward compatibility (ignore unknown fields), Simulated."),
    _registration("state_mgmt_11", "worker", "2026-10-09", "State 11: G-counter CRDT, Simulated."),
    _registration("state_mgmt_12", "worker", "2026-10-09", "State 12: operational transformation (mock), Simulated."),
    _registration("state_mgmt_13", "worker", "2026-10-09", "State 13: vector clocks, Simulated."),
    _registration("state_mgmt_14", "worker", "2026-10-09", "State 14: Lamport timestamps, Simulated."),
    _registration("state_mgmt_15", "worker", "2026-10-09", "State 15: hybrid logical clocks (mock), Simulated."),
    _registration("state_mgmt_16", "worker", "2026-10-09", "State 16: distributed snapshots (mock), Simulated."),
    _registration("state_mgmt_17", "worker", "2026-10-09", "State 17: Chandy-Lamport distributed snapshot (mock), Simulated."),
    _registration("state_mgmt_18", "worker", "2026-10-09", "State 18: consistent hashing ring."),
    _registration("state_mgmt_19", "worker", "2026-10-09", "State 19: gossip protocols (mock), Simulated."),
    _registration("state_mgmt_20", "worker", "2026-10-09", "State 20: anti-entropy (mock), Simulated."),
    _registration("state_mgmt_21", "worker", "2026-10-09", "State 21: Merkle-tree sync (mock), Simulated."),
    _registration("state_mgmt_22", "worker", "2026-10-09", "State 22: state reconciliation (mock), Simulated."),
    _registration("state_mgmt_23", "worker", "2026-10-09", "State 23: conflict resolution strategies."),
    _registration("state_mgmt_24", "worker", "2026-10-09", "State 24: last-write-wins register."),
    _registration("state_mgmt_25", "worker", "2026-10-09", "State 25: multi-value register."),
    _registration("state_mgmt_26", "worker", "2026-10-09", "State 26: OR-set (observed-remove set) CRDT."),
    _registration("state_mgmt_27", "worker", "2026-10-09", "State 27: 2P-set (two-phase set) CRDT."),
    _registration("state_mgmt_28", "worker", "2026-10-09", "State 28: LWW-map CRDT."),
    _registration("state_mgmt_29", "worker", "2026-10-09", "State 29: CRDT counters (G-counter + PN-counter)."),
    _registration("state_mgmt_30", "worker", "2026-10-09", "State 30: CRDT graphs (mock), Simulated."),
    _registration("stateful_veto", "stateful-veto", "2026-10-08", "Stateful veto: deny is a signal, not an endpoint (D8), Simulated."),
    _registration("static_verify", "ninety-first", "2026-10-04", "Static pre-dispatch verification of tool-call policies (ninety-first batch)."),
    _registration("status_page", "runtime", "2026-10-08", "Status page — Statuspage.io-shaped incident bookkeeping (batch-34 interface)."),
    _registration("steganography", "runtime", "2026-10-08", "steganography.py — hidden-message embedding/extraction/detection bookkeeping."),
    _registration("step_compliance", "bench", "2026-10-04", "in-toto-derived step compliance for multi-step bench tasks (offline)."),
    _registration("step_reliability_budget", "step-reliability-budget", "2026-11-14", "Step reliability budget: per-step success rate to run-level failure probability."),
    _registration("stomp_broker", "runtime", "2026-10-08", "STOMP (Simple Text Oriented Messaging Protocol) broker bookkeeping."),
    _registration("strands_checkpoint", "strands", "2026-11-14", "A versioned resume marker and hook-based retry, split from run state."),
    _registration("stream_guard", "one-hundred-sixth", "2026-10-04", "Streaming output guard: per-chunk screening, not final-output gating."),
    _registration("stream_join", "runtime", "2026-10-07", "Stream-stream temporal joins."),
    _registration("stream_processing", "runtime", "2026-10-08", "Stream processing: tumbling/sliding windows, keyed joins, aggregates."),
    _registration("streaming_sql", "runtime", "2026-10-07", "Streaming SQL interface (Flink-style windows and aggregations)."),
    _registration("structured_log", "runtime", "2026-10-07", "Structured JSON logging: level-gated, field-carrying log records."),
    _registration("structured_output", "structured-output", "2026-10-08", "Structured gate outputs: schema-enforced verdicts (XGrammar/Outlines), Simulated."),
    _registration("stuck_detector", "openhands-stuck-detector", "2026-11-14", "Stuck detector: five repetition patterns over Northstar session history."),
    _registration("subscription_manager", "runtime", "2026-10-08", "SaaS subscription manager: plans, trials, billing periods, cancellation (simulated)."),
    _registration("summarization_guard", "summarization-guard", "2026-10-09", "Summarization guard (D-OUT-020), Simulated."),
    _registration("superalignment", "runtime", "2026-10-08", "Superalignment research governance as a deterministic single-host decision ledger."),
    _registration("supplychain_agents", "one-hundred-forty-fourth", "2026-10-04", "Supply-chain AI discipline gates (one-hundred-forty-fourth batch)."),
    _registration("support_agents", "one-hundred-fifty-sixth", "2026-10-04", "Customer-service AI discipline (one-hundred-fifty-sixth batch)."),
    _registration("swe_failure_modes", "swe-failure-modes", "2026-11-14", "Failure-mode classifier for failed patches, with a per-mode check route."),
    _registration("swim_protocol", "runtime", "2026-10-07", "SWIM protocol: gossip-based membership and failure detection."),
    _registration("sycophancy", "runtime", "2026-10-08", "Sycophancy as a deterministic single-host decision ledger."),
    _registration("sycophancy_detector", "runtime", "2026-10-07", "Sycophancy detector: agreement vs source-deference channels."),
    _registration("symbolic_exec", "runtime", "2026-10-07", "Symbolic execution interface (toy IR, simulated)."),
    _registration("synthetic_cap", "one-hundred-twelfth", "2026-10-04", "Synthetic-data ratio cap (one-hundred-twelfth batch)."),
    _registration("synthetic_media", "runtime", "2026-10-08", "Synthetic media — synthetic-content generation/label/disclosure ledger."),
    _registration("synthetic_monitor", "runtime", "2026-10-08", "Synthetic monitoring — simulated uptime-check bookkeeping (thirty-second batch)."),
    _registration("system_card", "runtime", "2026-10-08", "System card: model system-documentation decision ledger, Simulated."),
    _registration("systemic_risk", "runtime", "2026-10-08", "Systemic-risk governance as a deterministic single-host decision ledger."),
    _registration("t_digest", "runtime", "2026-10-07", "T-digest: mergeable quantile estimation over streaming values."),
    _registration("task_manager", "runtime", "2026-10-08", "GTD task manager interface (Todoist-style task bookkeeping)."),
    _registration("task_queue", "runtime", "2026-10-07", "Task queue: Celery-style durable task dispatch bookkeeping."),
    _registration("task_router", "runtime", "2026-10-08", "Task router: deterministic task-to-worker routing, dispatch, and rebalancing."),
    _registration("task_snapshot", "task-snapshot", "2026-10-09", "Task snapshots: replayable forensic artifacts (AgentScope), Simulated."),
    _registration("tax_agents", "one-hundred-forty-eighth", "2026-10-04", "Tax & customs AI discipline (one-hundred-forty-eighth batch)."),
    _registration("tax_calculator", "runtime", "2026-10-08", "VAT / sales-tax calculator with jurisdiction rates and exemptions."),
    _registration("team_manager", "runtime", "2026-10-08", "Team manager interface (org teams: create / invite / roles)."),
    _registration("telecom_agents", "one-hundred-twenty-ninth", "2026-10-04", "Telecom AI discipline (one-hundred-twenty-ninth batch)."),
    _registration("template_engine", "runtime", "2026-10-08", "Template engine interface (Mustache / Jinja rendering discipline, simulated)."),
    _registration("temporal_decoupling_probe", "probes", "2026-10-07", "Temporal-decoupling probes: multi-session memory poisoning."),
    _registration("temporal_logic", "runtime", "2026-10-07", "Linear temporal logic (LTL) over finite traces: check one reported run."),
    _registration("tenant_billing", "runtime", "2026-10-08", "Tenant billing: multi-tenant usage metering and invoicing bookkeeping."),
    _registration("tenant_quotas", "runtime", "2026-10-08", "Per-tenant resource quotas: limits, enforcement, and resets."),
    _registration("terraform_provider", "runtime", "2026-10-07", "Terraform-style provider: desired-state plan/apply/destroy bookkeeping."),
    _registration("text_to_speech", "runtime", "2026-10-08", "Text-to-speech interface: voices/synthesize as deterministic bookkeeping."),
    _registration("threat_hunting", "runtime", "2026-10-08", "Threat hunting operations (hypothesis / hunt / validate bookkeeping, simulated)."),
    _registration("threat_intel", "runtime", "2026-10-08", "Cyber Threat Intelligence (CTI) lifecycle as a deterministic single-host decision ledger."),
    _registration("three_phase_commit", "runtime", "2026-10-07", "Three-phase commit: non-blocking distributed commit protocol."),
    _registration("threshold_sig", "runtime", "2026-10-07", "Threshold signature interface (FROST-style, simulated DKG)."),
    _registration("tile_server", "runtime", "2026-10-08", "Slippy-map tile addressing, in-memory."),
    _registration("time_series_db", "runtime", "2026-10-08", "Time-series database: InfluxDB-shaped write/query/downsample bookkeeping."),
    _registration("timelock_enc", "runtime", "2026-10-07", "Time-lock puzzles for future-dated decryption: timelock encryption."),
    _registration("timeout_management", "runtime", "2026-10-08", "Timeout management — gRPC-shaped deadline propagation bookkeeping."),
    _registration("timeout_manager", "runtime", "2026-10-07", "Safety timeout manager: enforce wall-clock deadlines on untrusted work."),
    _registration("timeseries_db", "runtime", "2026-10-07", "Time-series database (TSDB) interface (Prometheus/InfluxDB-style, single-host)."),
    _registration("timezone_resolver", "runtime", "2026-10-08", "Timezone resolver interface: lat/lon to IANA zone lookup."),
    _registration("tls_terminator", "runtime", "2026-10-07", "TLS terminator: edge handshake negotiation + SNI certificate selection + ALPN (simulated)."),
    _registration("token_counter", "runtime", "2026-10-08", "Token counting (count/estimate/truncate) interface, simulated."),
    _registration("tool_failure", "toolfail", "2026-11-13", "Typed tool-failure normalization: every failure becomes a remedy-carrying tool_result."),
    _registration("tool_input_schema", "harden agent runtime security and red-team governance", "2026-10-12", "Fail-closed validation for runtime tool arguments."),
    _registration("tool_output_filter", "tool-output-filter", "2026-11-14", "Filter tool outputs *in code* before they are allowed into a context."),
    _registration("tool_pinning", "tool-pinning", "2026-10-08", "Hash-pinned tool definitions (MCP rug-pull defense), Simulated."),
    _registration("tool_schema_digest_probes", "runtime", "2026-10-07", "Tool-schema-digest probes: per-invocation digests, drift detection, identity binding."),
    _registration("tool_system_01", "massive", "2026-10-09", "Tool discovery: registry with search, Simulated."),
    _registration("tool_system_02", "massive", "2026-10-09", "Tool versioning: semver checks, Simulated."),
    _registration("tool_system_03", "massive", "2026-10-09", "Tool deprecation: warnings, Simulated."),
    _registration("tool_system_04", "massive", "2026-10-09", "Tool composition: chain tools, Simulated."),
    _registration("tool_system_05", "worker", "2026-10-09", "Tool chaining: sequential execution, Simulated."),
    _registration("tool_system_06", "worker", "2026-10-09", "Parallel tool calls: mock concurrent, Simulated."),
    _registration("tool_system_07", "worker", "2026-10-09", "Tool retries: exponential backoff, Simulated."),
    _registration("tool_system_08", "worker", "2026-10-09", "Tool timeouts: mock, Simulated."),
    _registration("tool_system_09", "worker", "2026-10-09", "Tool caching: memoize results, Simulated."),
    _registration("tool_system_10", "worker", "2026-10-09", "Tool idempotency: idempotency keys, Simulated."),
    _registration("tool_system_11", "worker", "2026-10-09", "Tool transactions: mock 2PC, Simulated."),
    _registration("tool_system_12", "worker", "2026-10-09", "Tool sagas: compensating actions, Simulated."),
    _registration("tool_system_13", "worker", "2026-10-09", "Tool circuit breakers: fail fast, Simulated."),
    _registration("tool_system_14", "worker", "2026-10-09", "Tool bulkheads: isolation, Simulated."),
    _registration("tool_system_15", "worker", "2026-10-09", "Tool rate limiting: per-tool buckets, Simulated."),
    _registration("tool_system_16", "worker", "2026-10-09", "Tool quotas: per-tool usage limits, Simulated."),
    _registration("tool_system_17", "worker", "2026-10-09", "Tool billing (mock): per-tool call cost ledger, Simulated."),
    _registration("tool_system_18", "worker", "2026-10-09", "Tool analytics (mock): call/latency statistics, Simulated."),
    _registration("tool_system_19", "worker", "2026-10-09", "Tool A/B testing (mock): deterministic variant bucketing, Simulated."),
    _registration("tool_system_20", "worker", "2026-10-09", "Tool feature flags: boolean flags with rollouts, Simulated."),
    _registration("tool_system_21", "worker", "2026-10-09", "Tool canary deploys: staged percentage rollout, Simulated."),
    _registration("tool_system_22", "worker", "2026-10-09", "Tool blue-green deploys: two-slot state machine, Simulated."),
    _registration("tool_system_23", "worker", "2026-10-09", "Tool rollback manager: version history with pins, Simulated."),
    _registration("tool_system_24", "worker", "2026-10-09", "Tool health checks: registered checkables per tool, Simulated."),
    _registration("tool_system_25", "worker", "2026-10-09", "Tool documentation generator: markdown from specs, Simulated."),
    _registration("tool_system_26", "worker", "2026-10-09", "Tool playground (mock): sandboxed dry-run of a tool call, Simulated."),
    _registration("tool_system_27", "worker", "2026-10-09", "Tool marketplace (mock registry), Simulated."),
    _registration("tool_system_28", "worker", "2026-10-09", "Tool composition (advanced): chained pipelines with placeholder refs."),
    _registration("tool_system_29", "worker", "2026-10-09", "Tool orchestration (mock): DAG of tool tasks, Simulated."),
    _registration("tool_system_30", "worker", "2026-10-09", "Tool governance (policy): regex policies over tool names, Simulated."),
    _registration("tool_use", "runtime", "2026-10-08", "Tool-use (function calling) registration and invocation bookkeeping, simulated."),
    _registration("tools.__init__", "dx foundations", "2026-09-07", "Tool registry, uniform handler signature, and the sandbox every path crosses."),
    _registration("tools.capdrop", "sandbox", "2026-10-04", "Linux capability minimisation launcher for tool-effect subprocesses."),
    _registration("tools.code", "runtime", "2026-10-13", "Structured repository tools for the ``northstar code`` product path."),
    _registration("tools.effect_envelope", "governance", "2026-10-06", "Effect Envelope: unified path containment (Orrery Gate 2 style)."),
    _registration("tools.fetch", "network boundary", "2026-10-04", "Agent-facing network tool routed through the egress sidecar."),
    _registration("tools.os_sandbox", "runtime", "2026-09-09", "OS-level execution backends for governed command tools (Shell)."),
    _registration("tools.parallel", "runtime", "2026-09-09", "Classify which tools may share a concurrent execution batch."),
    _registration("tools.path_integrity", "path-shim red-team", "2026-10-04", "PATH-shim detection and tool-binary integrity pins."),
    _registration("tools.pledge", "pledge-style self-restriction", "2026-10-04", "Pledge-style self-restriction for tool-effect execution."),
    _registration("tools.resource_limits", "harden agent runtime security and red-team governance", "2026-10-12", "Per-process resource ceilings for Shell child processes."),
    _registration("tools.sandbox", "sandbox", "2026-10-04", "Linux Landlock unprivileged self-sandbox for the process backend."),
    _registration("tools.seccomp", "runtime", "2026-10-02", "Seccomp-BPF denylist for the sandbox backends."),
    _registration("tools.shell", "runtime", "2026-09-09", "Shell tool: governed command execution inside the OS sandbox."),
    _registration("tools.skill_scripts", "runtime", "2026-09-09", "Skill-bundled scripts: discoverable, sandboxed, never auto-run."),
    _registration("tools.systemd_scope", "harden agent runtime security and red-team governance", "2026-10-12", "Root-managed systemd scopes for aggregate Shell process-tree limits."),
    _registration("tools.verify_invariants", "runtime", "2026-09-07", "Revert each core guard in a throwaway copy of the component and confirm the match."),
    _registration("toxicity_mock", "toxicity-mock", "2026-10-09", "Toxicity detection mock (D-OUT-009), Simulated."),
    _registration("trace_export", "audit", "2026-10-03", "Export a Northstar audit chain head as a TRACE v0.2-shaped Trust Record."),
    _registration("trace_tamper_probes", "runtime", "2026-10-07", "Trace-tampering probe corpus + deletion / independence / integrity detectors."),
    _registration("traceability_paradox", "runtime", "2026-10-07", "Traceability paradox detector: the safety instrument as attack surface."),
    _registration("tracing", "add northstar-agent-runtime: governed agent loop on the claude a", "2026-09-06", "Span tree for a run: ``run -> turn[n] -> generation | tool:Name | subagent:Type``."),
    _registration("traffic_steering", "runtime", "2026-10-08", "Traffic steering: geo / latency / weighted routing bookkeeping (simulated)."),
    _registration("transaction_manager", "runtime", "2026-10-08", "Transaction manager: deterministic transaction lifecycle bookkeeping."),
    _registration("transactional_messaging", "runtime", "2026-10-08", "Transactional messaging: 2PC-shaped atomic message send."),
    _registration("translation_guard", "translation-guard", "2026-10-09", "Translation guard mock (D-OUT-021), Simulated."),
    _registration("transparency", "runtime", "2026-10-08", "Transparency: AI transparency-obligation disclosure ledger, Simulated."),
    _registration("transparency_log", "runtime", "2026-10-07", "Transparency log: append-only Merkle log in the Certificate Transparency style."),
    _registration("transport_agents", "one-hundred-fifty-third", "2026-10-04", "Transport & logistics AI discipline (one-hundred-fifty-third batch)."),
    _registration("traversal_detect", "traversal-detect", "2026-10-09", "Path traversal detection (D-OUT-026), Simulated."),
    _registration("treacherous_turn", "runtime", "2026-10-08", "Treacherous turn as a deterministic single-host decision ledger."),
    _registration("tripwire_guardrails", "tripwire", "2026-10-08", "Tripwire guardrails: three-valued gate outcomes (OpenAI Agents SDK), Simulated."),
    _registration("trojan", "runtime", "2026-10-08", "Trojan test/detect decision ledger, Simulated."),
    _registration("trojan_defense", "runtime", "2026-10-08", "Trojan defense: trojan remediation lifecycle ledger for models, Simulated."),
    _registration("trust_inversion_probes", "runtime", "2026-10-07", "Trust-inversion probe corpus + delegation-culture risk detectors + gate-strength calibration."),
    _registration("trust_safety", "runtime", "2026-10-08", "Trust & safety policy engine (twenty-ninth batch)."),
    _registration("trustworthy_ai", "runtime", "2026-10-08", "Trustworthy-AI assessment ledger (sixty-first batch)."),
    _registration("turn_truncation", "turn-truncation", "2026-11-14", "Turn truncation: an interrupted turn is recorded as the delivered prefix."),
    _registration("twin_receipts", "ninety-sixth", "2026-10-04", "Twin-sync receipts: freshness-gated actuation for digital twins (ninety-sixth batch)."),
    _registration("two_phase_commit", "runtime", "2026-10-07", "Two-phase commit (2PC): atomic commit across a participant cohort."),
    _registration("two_tier_gating", "two-tier-gating", "2026-10-08", "Two-tier gating: fast then expensive (LlamaFirewall), Simulated."),
    _registration("twopset", "runtime", "2026-10-08", "Two-Phase Set (2P-Set): add/remove with convergent merge."),
    _registration("type_checker", "runtime", "2026-10-07", "Simply-typed lambda calculus (STLC) type checker: check / infer."),
    _registration("type_checker_iface", "runtime", "2026-10-08", "Mypy-style type-checking interface (declared signatures vs reported calls)."),
    _registration("uncertainty_mock", "uncertainty-mock", "2026-10-09", "Uncertainty quantification mock (D-OUT-016), Simulated."),
    _registration("underwriting_agents", "one-hundred-fortieth", "2026-10-04", "Underwriting & claims discipline gates (one-hundred-fortieth batch)."),
    _registration("unicode_sanit", "unicode-sanit", "2026-10-09", "Unicode sanitization NFKC (D-IN-005), Simulated."),
    _registration("url_decode_guard", "url-decode-guard", "2026-10-09", "URL decoding guard (D-IN-008), Simulated."),
    _registration("user_profile", "runtime", "2026-10-08", "User profile records with per-field privacy levels, in-memory."),
    _registration("validator_scarcity", "runtime", "2026-10-07", "Validator scarcity detector."),
    _registration("value_learning", "runtime", "2026-10-08", "Value learning decision ledger, Simulated."),
    _registration("vdf_interface", "runtime", "2026-10-07", "Verifiable delay function (VDF) interface (Pietrzak-style, simulated)."),
    _registration("vector_clock", "runtime", "2026-10-07", "Vector clock: causality tracking across nodes."),
    _registration("vector_commitment", "runtime", "2026-10-07", "Vector commitment: stateless position-bound opening proofs."),
    _registration("vector_db", "runtime", "2026-10-07", "Brute-force vector database interface for embedding search."),
    _registration("vector_search", "runtime", "2026-10-08", "HNSW-shaped approximate nearest-neighbor index bookkeeping."),
    _registration("vendor_chain", "one-hundred-third", "2026-10-04", "Vendor-chain provenance receipts (one-hundred-third batch)."),
    _registration("vendor_risk", "runtime", "2026-10-08", "Vendor risk: third-party risk assessment and lifecycle ledger, Simulated."),
    _registration("verifiability_tier", "verifiability-tier", "2026-11-14", "Verifiability tiers: how checkable a claim is, not whether it is true."),
    _registration("verification", "add verified code-task workflow and offline benchmark pack", "2026-10-13", "Host-declared command checks for the programming-agent completion boundary."),
    _registration("verification_badges", "runtime", "2026-10-08", "Identity verification badges (twenty-ninth batch)."),
    _registration("verkle_tree", "runtime", "2026-10-07", "Verkle tree: authenticated key-value store with vector commitments."),
    _registration("version_manager", "runtime", "2026-10-08", "Version manager: semantic version parsing, comparison, and range checks."),
    _registration("video_analyzer", "runtime", "2026-10-08", "Video analyzer interface (scene detection + motion estimation, simulated)."),
    _registration("video_streaming", "runtime", "2026-10-08", "HLS/DASH adaptive-bitrate streaming bookkeeping, in-memory."),
    _registration("video_transcoder", "runtime", "2026-10-08", "FFmpeg-style video transcode bookkeeping, in-memory."),
    _registration("virtual_nodes", "runtime", "2026-10-08", "Virtual nodes: Dynamo/Cassandra-style vnode ownership bookkeeping."),
    _registration("vr_interface", "runtime", "2026-10-07", "Viewstamped Replication interface: primary/backup bookkeeping."),
    _registration("vrf_interface", "runtime", "2026-10-07", "Verifiable random function interface (simulated)."),
    _registration("vuln_disclosure", "runtime", "2026-10-08", "Vulnerability disclosure: coordinated vulnerability disclosure (CVD) ledger, Simulated."),
    _registration("vuln_scanner", "runtime", "2026-10-08", "Vulnerability scanner: software inventory x CVE database matching (simulated)."),
    _registration("waf_rules", "runtime", "2026-10-08", "Web-application-firewall rule bookkeeping (OWASP CRS-shaped)."),
    _registration("waste_agents", "one-hundred-thirty-ninth", "2026-10-04", "Waste & circular-economy discipline (one-hundred-thirty-ninth batch)."),
    _registration("water_agents", "one-hundred-thirty-first", "2026-10-04", "Water-infrastructure defense gates (one-hundred-thirty-first batch)."),
    _registration("watermark", "runtime", "2026-10-08", "watermark: AI-generated content watermarking decision ledger."),
    _registration("watermark_tracker", "runtime", "2026-10-07", "Event-time watermark tracking (Flink-style) over caller-supplied time."),
    _registration("watermark_verifier", "runtime", "2026-10-07", "Model watermark verifier: provenance for generated content."),
    _registration("weak_to_strong", "runtime", "2026-10-07", "Weak-to-strong generalization monitor."),
    _registration("weak_to_strong_v2", "runtime", "2026-10-08", "Weak-to-strong generalization governance ledger, Simulated."),
    _registration("weather_service", "runtime", "2026-10-08", "Weather service: simulated current/forecast/alert bookkeeping (Open-Meteo/NWS lineage)."),
    _registration("webhook_delivery", "runtime", "2026-10-08", "Webhook delivery attempts and signature verification: Svix-shaped bookkeeping."),
    _registration("webhook_dispatcher", "runtime", "2026-10-07", "Webhook dispatcher: signed endpoint callbacks with deterministic retry bookkeeping."),
    _registration("webhook_manager", "runtime", "2026-10-08", "Webhook registration and delivery bookkeeping: retries with a ledger."),
    _registration("websocket_gateway", "runtime", "2026-10-07", "WebSocket gateway: simulated RFC 6455 connection ledger."),
    _registration("websocket_manager", "runtime", "2026-10-08", "WebSocket connection, room, and broadcast bookkeeping (Socket.io-shaped)."),
    _registration("white_label", "runtime", "2026-10-08", "White-label branding: tenant themes, custom domains, and brand assets."),
    _registration("wireheading", "runtime", "2026-10-08", "Wireheading: reward-channel self-tampering detection ledger, Simulated."),
    _registration("witness_enc", "runtime", "2026-10-07", "Simulated witness encryption (API + bookkeeping, NOT real crypto)."),
    _registration("workflow_automation", "runtime", "2026-10-08", "Workflow automation: Zapier-shaped trigger-to-action chain bookkeeping."),
    _registration("workflow_engine", "runtime", "2026-10-07", "Workflow engine: DAG-shaped step execution with per-step retries."),
    _registration("workflow_orchestration", "runtime", "2026-10-08", "Workflow orchestration (Airflow/Temporal-shaped control plane)."),
    _registration("write_ahead_log", "runtime", "2026-10-07", "Write-ahead log: crash-recovery log with verified checkpoints."),
    _registration("write_through_cache", "runtime", "2026-10-08", "Write-through cache: every write lands on the backing store and the cache."),
    _registration("ws_norm", "ws-norm", "2026-10-09", "Whitespace normalization (D-IN-018), Simulated."),
    _registration("xss_detect", "xss-detect", "2026-10-09", "XSS detection in output (D-OUT-024), Simulated."),
    _registration("xxe_detect", "xxe-detect", "2026-10-09", "XXE detection (D-OUT-028), Simulated."),
    _registration("zab_interface", "runtime", "2026-10-07", "ZooKeeper atomic broadcast (Zab) interface: proposal/ack/commit bookkeeping."),
    _registration("zero_knowledge", "runtime", "2026-10-08", "zero_knowledge.py — zero-knowledge proving-system lifecycle bookkeeping."),
    _registration("zeromq_patterns", "runtime", "2026-10-08", "ZeroMQ messaging patterns bookkeeping (simulated)."),
    _registration("zk_interface", "runtime", "2026-10-07", "Zero-knowledge proof prover interface for verifiable computation."),
    _registration("zk_verifier", "runtime", "2026-10-07", "Zero-knowledge proof verifier interface for verifiable computation."),
    _registration("zw_remove", "zw-remove", "2026-10-09", "Zero-width removal (D-IN-017), Simulated."),
)


def registered_modules():
    """Return the registry as a tuple of :class:`Registration` records.

    The tuple is returned as-is: it is immutable, and so are the records
    inside it, so the caller cannot mutate the registry by accident.
    """
    return REGISTRY


def registered_module_names():
    """Return the registered module names, sorted."""
    return tuple(record.module for record in REGISTRY)


def registration_for(module):
    """Return the :class:`Registration` for ``module``.

    Raises ``KeyError`` when the module is not registered, naming it.
    """
    for record in REGISTRY:
        if record.module == module:
            return record
    raise KeyError("module %r is not registered" % (module,))


def declared_py_modules(pyproject=PYPROJECT):
    """Return the module names declared in ``pyproject.toml``'s py-modules.

    The file is read, never written.  A missing or malformed file raises
    :class:`RegistrationError` rather than a bare ``KeyError``.
    """
    try:
        data = tomllib.loads(Path(pyproject).read_text(encoding="utf-8"))
    except OSError as exc:
        raise RegistrationError("cannot read %s: %s" % (pyproject, exc)) from exc
    except tomllib.TOMLDecodeError as exc:
        raise RegistrationError("cannot parse %s: %s" % (pyproject, exc)) from exc
    try:
        modules = data["tool"]["setuptools"]["py-modules"]
    except KeyError as exc:
        raise RegistrationError(
            "%s has no [tool.setuptools] py-modules array" % (pyproject,)
        ) from exc
    return tuple(modules)


def flat_modules_on_disk(component=COMPONENT):
    """Return the flat runtime module names that exist as ``*.py`` on disk.

    The two excluded files are the ones ``tests/test_module_layout.py``
    excludes as well, so the two views agree by construction.
    """
    component = Path(component)
    return tuple(
        sorted(
            path.stem
            for path in component.glob("*.py")
            if path.is_file()
            and path.name not in NON_RUNTIME_MODULES
            and not path.name.startswith("test_")
        )
    )


def declared_package_patterns(pyproject=PYPROJECT):
    """Return the package-name patterns setuptools' ``packages.find`` installs.

    ``py-modules`` lists FLAT module names only, so a package's members
    cannot appear there.  They are installed through a second mechanism::

        [tool.setuptools.packages.find]
        where = ["."]
        include = ["providers*", "tools*"]

    This reads that second mechanism, so the installed surface is derived
    from the packaging configuration rather than from a hand-maintained list
    of package names.
    """
    try:
        data = tomllib.loads(Path(pyproject).read_text(encoding="utf-8"))
    except OSError as exc:
        raise RegistrationError("cannot read %s: %s" % (pyproject, exc)) from exc
    except tomllib.TOMLDecodeError as exc:
        raise RegistrationError("cannot parse %s: %s" % (pyproject, exc)) from exc
    try:
        find = data["tool"]["setuptools"]["packages"]["find"]
    except KeyError:
        # A component with no packages is a component with no package
        # members: an empty answer, not an error.
        return ()
    include = find.get("include", [])
    return tuple(pattern for pattern in include if isinstance(pattern, str))


def modules_on_disk(component=COMPONENT, pyproject=PYPROJECT):
    """Return every runtime module name that exists on disk.

    Two shapes, because the component has two kinds of runtime module:

    * a **flat** module -- the file stem at the component root;
    * a **package member** -- ``tools.shell``, a module inside a package
      directory, named with its package prefix.

    The package members are the ones the packaging configuration installs
    through ``packages.find``; the flat ones through ``py-modules``.  A
    view that listed only the flat ones would miss 22 of the runtime's
    modules -- including ``tools.shell``.
    """
    return tuple(
        sorted(
            set(flat_modules_on_disk(component))
            | set(package_members_on_disk(component, pyproject))
        )
    )


def package_members_on_disk(component=COMPONENT, pyproject=PYPROJECT):
    """Return the installed members of the component's packages.

    A package's own module is a member too (``tools.__init__`` carries the
    tool registry), so it is included.

    The package set comes from ``pyproject.toml``'s ``packages.find``
    ``include`` patterns, so a package added to the configuration is
    covered automatically -- there is no second list to keep in step.
    """
    component = Path(component)
    stems = {pattern.rstrip("*") for pattern in declared_package_patterns(pyproject)}
    found: set[str] = set()
    for stem in sorted(stems):
        package_dir = component / stem
        if not (package_dir / "__init__.py").is_file():
            continue
        found.add("%s.__init__" % stem)
        for path in sorted(package_dir.glob("*.py")):
            if path.name != "__init__.py":
                found.add("%s.%s" % (stem, path.stem))
    return tuple(sorted(found))


def installed_modules(component=COMPONENT, pyproject=PYPROJECT):
    """Return every module ``pip install .`` makes importable.

    This is the union of the two installation mechanisms: the flat
    ``py-modules`` array and the members of the packages setuptools finds.
    It is the surface the registry has to cover.
    """
    flat = set(declared_py_modules(pyproject))
    return tuple(sorted(flat | set(package_members_on_disk(component, pyproject))))


def assert_registration_matches_installed(
    component=COMPONENT, pyproject=PYPROJECT, registry=REGISTRY
):
    """Require the registry to cover the whole *installed* surface.

    ``assert_registration_matches_disk`` compares three views -- the
    registry, ``py-modules`` and the flat ``*.py`` files -- and all three
    are blind to the package members, because a package's members cannot
    appear in ``py-modules`` and are not flat files.

    So the closure could be "complete" over 1613 modules while the
    component shipped 1635.  This check closes that hole: it requires the
    registry to name every installed module, and raises
    :class:`RegistrationError` naming each one that it does not.

    Returns the tuple of installed module names when the registry covers
    them.
    """
    registry_set = {record.module for record in registry}
    installed = installed_modules(component, pyproject)
    unregistered = sorted(name for name in installed if name not in registry_set)
    if unregistered:
        raise RegistrationError(
            "runtime module registration does not cover the installed "
            "surface: module(s) installed but not in the registry: %s"
            % ", ".join(unregistered)
        )
    return installed


def assert_registration_matches_disk(
    component=COMPONENT, pyproject=PYPROJECT, registry=REGISTRY
):
    """Require the registry, ``pyproject.toml`` and the disk to agree.

    Four views must agree:

    * the module names in the registry,
    * the module names declared in ``pyproject.toml``'s ``py-modules``,
    * the ``*.py`` files in the component directory,
    * the members of the packages setuptools' ``packages.find`` installs.

    The fourth view is the one that was missing.  ``py-modules`` lists FLAT
    names only, so a package's members cannot appear there; setuptools
    installs them through ``packages.find``.  Without the fourth view the
    closure could be "complete" over 1613 modules while the component
    shipped 1635 -- and the 22 it missed included ``tools.shell``.

    Raises :class:`RegistrationError` naming every module that is in one
    view but not another.  The message names the offending modules, so a
    failure says which line of ``pyproject.toml`` has to be added.

    Returns the tuple of registered module names when the views agree.
    """
    registry_names = tuple(record.module for record in registry)
    declared = tuple(declared_py_modules(pyproject))
    on_disk = tuple(modules_on_disk(component))
    members = tuple(package_members_on_disk(component, pyproject))

    registry_set = set(registry_names)
    declared_set = set(declared)
    disk_set = set(on_disk)
    member_set = set(members)
    installed_set = declared_set | member_set

    problems = []
    unregistered = sorted(disk_set - registry_set)
    if unregistered:
        problems.append(
            "module(s) on disk but not in the registry: %s" % ", ".join(unregistered)
        )
    undeclared = sorted(registry_set - declared_set - member_set)
    if undeclared:
        problems.append(
            "module(s) in the registry but not in py-modules: %s" % ", ".join(undeclared)
        )
    not_packaged = sorted(disk_set - declared_set - member_set)
    if not_packaged:
        problems.append(
            "module(s) on disk but not in py-modules: %s" % ", ".join(not_packaged)
        )
    missing_from_disk = sorted(declared_set - disk_set)
    if missing_from_disk:
        problems.append(
            "module(s) in py-modules but not on disk: %s" % ", ".join(missing_from_disk)
        )
    # The installed-surface directions.  A package member that is on disk
    # but not installed is a module the wheel does not ship; one that is
    # installed but not registered is the gap this slice closes.
    unpackaged_members = sorted(member_set - installed_set)
    if unpackaged_members:
        problems.append(
            "package member(s) on disk but not installed: %s"
            % ", ".join(unpackaged_members)
        )
    unregistered_members = sorted(installed_set - registry_set)
    if unregistered_members:
        problems.append(
            "module(s) installed but not in the registry: %s"
            % ", ".join(unregistered_members)
        )
    phantom = sorted(registry_set - disk_set - member_set)
    if phantom:
        problems.append(
            "module(s) in the registry but not on disk: %s" % ", ".join(phantom)
        )

    if problems:
        raise RegistrationError(
            "runtime module registration does not match the disk: "
            + "; ".join(problems)
        )
    return registry_names
