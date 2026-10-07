"""Docstring-based API reference generator and documentation checker.

This is the "build" half of the repository's four-layer documentation
structure (quick start in the READMEs -> concepts -> guides -> API reference):

* ``build`` regenerates ``docs/api/<component>.md`` from the docstrings of each
  component's public modules (pure ``ast``: nothing is imported, so the build
  is hermetic and works offline with the standard library only);
* ``verify`` checks, without writing, that the committed API pages are fresh
  (byte-identical to what the generator produces) and that every internal
  markdown link in the repository resolves to an existing file.

The same checks run as unit tests (``tests/test_docbuild.py``) under
``make test`` and are repeated by the CI documentation job (structure tests +
this build/link check).

Usage:
    python3 tests/docbuild.py build     # regenerate docs/api/*.md
    python3 tests/docbuild.py verify    # freshness + links; exit 1 on drift
"""
from __future__ import annotations

import ast
import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "docs" / "api"

# component name (docs/api slug and directory name) -> public modules.
# Modules are listed explicitly on purpose: an added public module must be
# consciously exposed in the API reference (and the freshness check then keeps
# it there).
MANIFEST: dict[str, tuple[str, ...]] = {
    "northstar-run-contract": ("contract", "binding", "adapter", "audit", "policy"),
    "northstar-run-evidence": (
        "evidence_contract",
        "evidence_chain",
        "evidence_store",
        "sealed_receipt",
        "audit_adapter",
        "evidence_cli",
    ),
    "northstar-host": ("authorization", "workspace", "host_audit", "host_policy"),
    "northstar-durable-run": (
        "durable_contract",
        "event_store",
        "action_gateway",
        "runner",
        "verifier",
        "trace_metrics",
        "evaluation",
        "durable_audit",
        "tool_ledger",
        "blob_store",
        "event_migration",
        "tool_allowlist",
        "timelock",
        "tool_receipt",
        "receipt_gate",
        "governed_memory",
    ),
    "northstar-agent-interop": (
        "interop_contract",
        "handoff",
        "interop_adapter",
        "canary",
        "process_adapter",
        "process_backend",
        "remote_worker",
    ),
    "northstar-codex-sidecar": ("sidecar", "transport", "service", "sidecar_socket"),
    "northstar-egress-sidecar": ("egress_sidecar", "egress_socket", "transport"),
                            "northstar-agent-runtime": (
        "a2a_budget_combo", "a2a_gates", "a2abreak_probes", "action_card",
        "action_verifier", "adjudication", "adtech_agents", "adversarial_detector",
        "agb_smoke_corpus", "agent_files", "agent_identity", "agent_readiness",
        "agents", "agri", "agrifood_agents", "akf_export",
        "approval_chain", "approval_chain_time", "approval_sla", "approval_sla_time",
        "approver_separation", "asi04_probes", "asi07_corpus", "asi08_probes",
        "asi09_probes", "attested_receipts", "audit_agents", "audit_archive",
        "audit_chain", "audit_cli", "audit_export", "audit_merkle",
        "audit_rekor", "audit_scitt", "backdoor_detector", "bloom_filter",
        "blue_green_deploy", "booking_agents", "budget", "budget_approval_combo",
        "budget_combo", "budget_token_bucket", "bulkhead", "canary_controller",
        "canonical_json", "capability_reassembly", "capability_warrants", "cci_detector",
        "checkpoints", "circuit_breaker", "claimed_auth_corpus", "cli",
        "command_hooks", "commerce", "compaction", "compaction_approval_combo",
        "compaction_masking", "companionship", "compute_budget", "consensus_interface",
        "consent_receipts", "consistent_hash", "constitutional_monitor", "construction_agents",
        "contract_bridge", "count_min_sketch", "cqrs_pattern", "crdt_interface",
        "credential_detector", "crypto_agility", "data_poisoning_detector", "dataflow_policy",
        "dating_agents", "debate_protocol", "deception_detector", "decision_model",
        "defense_agents", "delegation_credentials", "deny_monotonicity", "deployment_registry",
        "disaster_agents", "distributed_lock", "doctor", "dp_accountant",
        "drift_probe", "dual_use", "durable_bridge", "ed25519",
        "edge_gate", "edge_gate_ml", "edge_memory_combo", "editorial",
        "education_agents", "egress_client", "egress_enforcer", "eldercare_agents",
        "embodied", "energybid_agents", "env_cost", "evaluator_access",
        "evasion_corpus", "event_sourcing", "events", "evidence_tiers",
        "exploit_difficulty", "failure_budget_combo", "failure_bundle", "feature_flags",
        "federated_attack_detector", "fhe_wrapper", "finance_agents", "forest_fish",
        "frontmatter", "game_agents", "gossip_protocol", "governance_bench",
        "govservices_agents", "graceful_shutdown", "greenwash", "grid_agents",
        "harness_binding", "health_checker", "healthcare_agents", "herd_gate",
        "hlc", "hooks", "housing", "housing_ai_agents",
        "hr_agents", "hyperloglog", "idempotency_manager", "identity_approval_combo",
        "identity_disclosure", "incident_receipts", "injection_detector", "insurance",
        "interop_bridge", "interpretability_probe", "iterated_amplification", "kill_approval_combo",
        "kill_switch", "kill_switch_distributed", "labor_algo", "language_cap",
        "leader_election", "legal_agents", "licensing", "loop",
        "mandate_credentials", "manufacturing_agents", "masdrift_corpus", "mcp_admission",
        "mcp_approval_combo", "mcp_client", "mcp_combo", "mcp_config",
        "mcp_drift_monitor", "mcp_elicitation", "mcp_negotiate", "mcp_pivoting_detector",
        "mcp_semantic_diff", "membership_inference_detector", "memory", "memory_admission",
        "memory_bitemporal", "memory_budget_combo", "memory_capability", "memory_combo",
        "memory_fact_belief", "memory_flat_vs_graph", "memory_safety", "message_signing",
        "mining_agents", "model_extraction_detector", "model_lineage", "moderation_agents",
        "multisig", "newsmedia_agents", "no_token_monitor", "offline_bundle",
        "orbital_agents", "outbox_pattern", "passport", "per_call_budget",
        "permissions", "permit_agents", "pharma_agents", "phi_detector",
        "plan_defense", "planner_budget_combo", "planner_gates", "plugin_load",
        "plugin_manifest", "plugin_trust", "pocketos_probe", "policy_file",
        "post_dispatch_monitor", "postconditions", "probe_defense_combo", "probe_flywheel",
        "process_receipts", "procurement_agents", "product_path", "prompt_stealing_detector",
        "proptech_agents", "provenance_taint", "provider_retry", "providers.__init__",
        "providers.anthropic", "providers.base", "providers.openai_compat", "providers.scripted",
        "quantum_timeline", "rate_limiter", "recursive_reward", "refusal_monitor",
        "retail_agents", "retry_policy", "rule_of_two_probe", "run_setup",
        "sae_interface", "safety_envelope", "saga_pattern", "scaffold",
        "scalable_oversight", "scene_bound", "science_agents", "sdk",
        "secure_aggregation", "session_lease", "session_replay", "session_ui",
        "session_view", "sessions", "sidecar_client", "signed_receipt_reflux",
        "silent_profiling_detector", "skill_audit", "skill_budget_combo", "skill_check",
        "skill_scanner", "skill_wiring", "skills", "soc_verdicts",
        "sports_agents", "static_verify", "step_compliance", "stream_guard",
        "supplychain_agents", "support_agents", "swim_protocol", "sycophancy_detector",
        "synthetic_cap", "t_digest", "tax_agents", "telecom_agents",
        "temporal_decoupling_probe", "timeout_manager", "tools.__init__", "tools.capdrop",
        "tools.effect_envelope", "tools.fetch", "tools.os_sandbox", "tools.parallel",
        "tools.path_integrity", "tools.pledge", "tools.sandbox", "tools.seccomp",
        "tools.shell", "tools.skill_scripts", "tools.verify_invariants", "trace_export",
        "traceability_paradox", "tracing", "transport_agents", "twin_receipts",
        "underwriting_agents", "validator_scarcity", "vector_clock", "vendor_chain",
        "waste_agents", "water_agents", "watermark_verifier", "weak_to_strong",
        "zk_verifier",
        "approval_fatigue_probes",
        "argument_smuggling_probes",
        "artifact_graph_probes",
        "ask_or_solve_probes",
        "benchmark_retirement_probes",
        "commerce_mandate_probes",
        "constraint_synthesis_probes",
        "counterfactual",
        "counterfactual_explanation_probes",
        "destructive_prefix_probes",
        "enforcement_gap_probes",
        "evidence_aging_probes",
        "evidence_compaction_probes",
        "history_deviation_probes",
        "memory_admission_probes",
        "monitor_channel_probes",
        "monitor_deafness_probes",
        "multi_axis_autonomy_probes",
        "negotiation_corpus_probes",
        "per_action_autonomy_probes",
        "plan_injection_probes",
        "planner_executor_seam_probes",
        "pre_completion_signal_probes",
        "privilege_at_recall_probes",
        "refusal_pattern_probes",
        "run_assert_eval_probes",
        "self_modification_probes",
        "self_referential_trust_probes",
        "sleeper_agent_probes",
        "stale_plan_probes",
        "tool_schema_digest_probes",
        "trace_tamper_probes",
        "trust_inversion_probes",
    ),
}

GENERATED_HEADER = (
    "<!-- GENERATED by tests/docbuild.py - do not edit; run `python3 tests/docbuild.py build` -->"
)

_SELF_ARGUMENTS = {"self", "cls", "mcs"}
_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
_FENCE_RE = re.compile(r"^(`{3,}|~{3,})")

# Relative-to-README link anchors each component README must offer (see
# tests/test_docbuild.py): one concepts page, one guides page, its own API page.
CONCEPTS_LINK = "../../docs/concepts/governance.md"
GUIDES_LINK = "../../docs/guides/packaging-and-ci.md"


def _summary(docstring: str | None, *, cap: int = 300) -> str:
    """First paragraph of a cleaned docstring, truncated for a reference page."""
    if not docstring:
        return ""
    text = docstring.strip().split("\n\n", 1)[0].replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > cap:
        text = text[: cap - 1].rstrip() + "\u2026"
    return text


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> str:
    """Render a callable's parameter list from the AST (annotations included)."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = node.args
        # Drop the leading self/cls so method signatures read naturally.
        positionals = list(args.posonlyargs) + list(args.args)
        dropped = positionals and positionals[0].arg in _SELF_ARGUMENTS
        if dropped:
            rebuilt = ast.arguments(
                posonlyargs=args.posonlyargs[1:] if args.posonlyargs else [],
                args=args.args[1:] if not args.posonlyargs else args.args,
                vararg=args.vararg,
                kwonlyargs=args.kwonlyargs,
                kw_defaults=args.kw_defaults,
                kwarg=args.kwarg,
                defaults=args.defaults,
            )
            args = rebuilt
        try:
            params = ast.unparse(args)
        except Exception:  # pragma: no cover - malformed AST edge
            params = "\u2026"
        prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
        return f"{prefix}{node.name}({params})"
    return f"{node.name}()"


def _is_property(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Recognize property-like decorators so references do not show ``()``."""
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in {"property", "cached_property"}:
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr in {"property", "cached_property"}:
            return True
    return False


def _module_id(component: str, module: str) -> str:
    return module.replace(".__init__", "").replace("/", ".")


def _render_module(component: str, module: str, source: Path) -> list[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    lines: list[str] = []
    heading = _module_id(component, module)
    lines.append(f"### `{heading}`")
    lines.append("")
    lines.append(f"Source: `{source.relative_to(ROOT).as_posix()}`")
    lines.append("")
    doc = ast.get_docstring(tree, clean=True)
    if doc:
        lines.append(_summary(doc))
        lines.append("")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            lines.append(f"#### `{_signature(node)}`")
            summary = _summary(ast.get_docstring(node, clean=True))
            if summary:
                lines.append("")
                lines.append(summary)
            lines.append("")
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            lines.append(f"#### `{node.name}`")
            summary = _summary(ast.get_docstring(node, clean=True))
            if summary:
                lines.append("")
                lines.append(summary)
            lines.append("")
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and not member.name.startswith("_"):
                    signature = f"`{member.name}` (property)" if _is_property(member) else f"`{_signature(member)}`"
                    lines.append(f"- {signature}")
                    member_summary = _summary(ast.get_docstring(member, clean=True), cap=200)
                    if member_summary:
                        lines.append(f"  - {member_summary}")
    return lines


def render_page(component: str) -> str:
    """Render the full API reference page for one component."""
    component_dir = ROOT / "components" / component
    readme = component_dir / "README.md"
    lines = [
        f"# {component} - API reference",
        "",
        GENERATED_HEADER,
        "",
        "Docstring-generated reference over the component's public modules "
        "(``ast``-extracted; nothing is imported, so this builds offline with the "
        "standard library). The README is the quick start and integration guide:",
        "",
        f"- [README (quick start)](../../components/{component}/README.md)",
        f"- [Concepts](../../docs/concepts/governance.md) and "
        f"[guides](../../docs/guides/governed-run-cookbook.md)",
        "",
        "## Modules",
        "",
    ]
    for module in MANIFEST[component]:
        source = component_dir / Path(*module.split(".")).with_suffix(".py")
        if module.endswith(".__init__"):
            source = component_dir / Path(module.removesuffix(".__init__")) / "__init__.py"
        if not source.is_file():
            raise FileNotFoundError(f"manifest module not found: {source}")
        lines += _render_module(component, module, source)
    # Drop trailing blank lines, keep exactly one final newline.
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


#: Public modules deliberately left out of the API reference, per component.
#: "listed explicitly on purpose" is only a true statement if forgetting is loud, so
#: a module that is neither in MANIFEST nor listed here fails the coverage test. An
#: exclusion is a recorded decision, not a parking spot: ``_version`` is generated at
#: build time and has no docstring worth publishing.
MANIFEST_EXCLUSIONS: dict[str, frozenset[str]] = {
    "northstar-agent-runtime": frozenset({"_version", "_domain_base"}),
}


def public_modules(component: str) -> set[str]:
    """Every importable module name a component exposes, by filename.

    Pure filesystem inspection, no imports: this file must run on a bare interpreter and
    must never execute component code just to document it.
    """
    root = ROOT / "components" / component
    found = {path.stem for path in root.glob("*.py")} - {"__init__", "__main__"}
    for package in sorted(path for path in root.iterdir() if (path / "__init__.py").exists()):
        # A package's own module is documentable (``tools.__init__`` carries the registry),
        # so it is part of the public surface; only the *component* root's ``__init__`` is
        # plumbing.
        found.add(f"{package.name}.__init__")
        for path in package.glob("*.py"):
            if path.name != "__init__.py":
                found.add(f"{package.name}.{path.stem}")
    return found


def undocumented_modules() -> list[str]:
    """``component: module`` pairs that are on disk but in neither manifest nor exclusions."""
    gaps: list[str] = []
    for component, modules in MANIFEST.items():
        if not (ROOT / "components" / component).is_dir():
            continue
        gaps.extend(
            f"{component}: {name}"
            for name in sorted(
                public_modules(component) - set(modules) - set(MANIFEST_EXCLUSIONS.get(component, frozenset()))
            )
        )
    return gaps


def documented_but_absent() -> list[str]:
    """The other direction: a page that documents a module which no longer exists."""
    ghosts: list[str] = []
    for component, modules in MANIFEST.items():
        root = ROOT / "components" / component
        if not root.is_dir():
            continue
        present = public_modules(component)
        ghosts.extend(f"{component}: {name}" for name in sorted(set(modules) - present))
    return ghosts


def build_all() -> dict[str, str]:
    """Return {component: page text} for every component in the manifest."""
    return {component: render_page(component) for component in MANIFEST}


def write_all() -> list[Path]:
    """Regenerate docs/api/*.md on disk; returns the written paths."""
    written: list[Path] = []
    for component, text in build_all().items():
        path = API_DIR / f"{component}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


def stale_pages() -> list[str]:
    """Names of committed API pages that differ from a fresh generation."""
    stale: list[str] = []
    for component, text in build_all().items():
        path = API_DIR / f"{component}.md"
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            stale.append(component)
    return stale


# Top-level directories whose markdown is not this repository's documentation. `research/`
# holds verbatim captures of third-party pages (their links point at the original sites, not
# at files here), so checking them would report the source site's navigation as broken links.
LINK_CHECK_EXCLUDED_ROOTS: frozenset[str] = frozenset({"research"})


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if ".git" not in path.parts
        and "node_modules" not in path.parts
        and path.relative_to(ROOT).parts[0] not in LINK_CHECK_EXCLUDED_ROOTS
    )


def broken_links() -> list[str]:
    """Every internal markdown link that does not resolve to an existing path.

    Code fences are skipped; external URLs, fragment-only anchors and mailto:
    links are not checked. Reported as ``<file>: <target>``.
    """
    broken: list[str] = []
    for path in markdown_files():
        in_fence = False
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _FENCE_RE.match(raw):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in _LINK_RE.finditer(raw):
                target = match.group(1).strip().strip("<>").strip()
                if not target or target.startswith(("#", "http://", "https://", "mailto:", "//")):
                    continue
                bare = urllib.parse.unquote(target.split("#", 1)[0]).strip()
                if not bare:
                    continue
                resolved = (path.parent / bare).resolve()
                if not resolved.exists():
                    broken.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {target}")
    return broken


def verify() -> int:
    """Freshness + links check used by CI and by the unit tests."""
    stale = stale_pages()
    links = broken_links()
    print(f"api pages: {len(MANIFEST)} components, modules "
          f"{sum(len(m) for m in MANIFEST.values())}")
    if stale:
        print("stale (run `python3 tests/docbuild.py build`):")
        for name in stale:
            print(f"  - docs/api/{name}.md")
    print(f"markdown files checked: {len(markdown_files())}")
    if links:
        print("broken links:")
        for entry in links:
            print(f"  - {entry}")
    if stale or links:
        print("documentation build FAILED")
        return 1
    print("documentation build OK (fresh + links resolve)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0] not in {"build", "verify"}:
        print(__doc__)
        return 2
    if args[0] == "build":
        for path in write_all():
            print(f"wrote {path.relative_to(ROOT).as_posix()}")
        return 0
    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
