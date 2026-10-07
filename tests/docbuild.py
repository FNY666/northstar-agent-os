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
        "agb_smoke_corpus",
        "a2abreak_probes",
        "asi04_probes",
        "asi08_probes",
        "asi09_probes",
        "crypto_agility",
        "evasion_corpus",
        "message_signing",
        "pocketos_probe",
        "temporal_decoupling_probe",
        "rule_of_two_probe",
        "deny_monotonicity",
        "adjudication",
        "asi07_corpus",
        "masdrift_corpus",
        "claimed_auth_corpus",
        "post_dispatch_monitor",
        "capability_warrants",
        "embodied",
        "greenwash",
        "mandate_credentials",
        "orbital_agents",
        "procurement_agents",
        "hr_agents",
        "waste_agents",
        "adtech_agents",
        "energybid_agents",
        "underwriting_agents",
        "disaster_agents",
        "pharma_agents",
        "legal_agents",
        "govservices_agents",
        "moderation_agents",
        "manufacturing_agents",
        "construction_agents",
        "housing_ai_agents",
        "supplychain_agents",
        "audit_agents",
        "tax_agents",
        "permit_agents",
        "water_agents",
        "grid_agents",
        "licensing",
        "mining_agents",
        "labor_algo",
        "forest_fish",
        "telecom_agents",
        "approver_separation",
        "attested_receipts",
        "agent_readiness",
        "agents",
        "agent_files",
        "agent_identity",
        "identity_disclosure",
        "kill_switch",
        "mcp_semantic_diff",
        "cci_detector",
        "credential_detector",
        "sycophancy_detector",
        "deception_detector",
        "injection_detector",
        "memory_combo",
        "mcp_combo",
        "budget_combo",
        "approval_chain",
        "mcp_pivoting_detector",
        "skill_scanner",
        "approval_sla_time",
        "budget_token_bucket",
        "memory_capability",
        "a2a_gates",
        "plan_defense",
        "probe_flywheel",
        "memory_fact_belief",
        "skill_wiring",
        "planner_gates",
        "failure_bundle",
        "edge_gate",
        "compaction_masking",
        "memory_bitemporal",
        "signed_receipt_reflux",
        "per_call_budget",
        "memory_admission",
        "mcp_drift_monitor",
        "approval_sla",
        "agri",
        "booking_agents",
        "budget",
        "canonical_json",
        "checkpoints",
        "commerce",
        "cli",
        "command_hooks",
        "compaction",
        "companionship",
        "compute_budget",
        "consent_receipts",
        "contract_bridge",
        "doctor",
        "drift_probe",
        "durable_bridge",
        "egress_client",
        "egress_enforcer",
        "interop_bridge",
        "memory",
        "memory_safety",
        "model_lineage",
        "events",
        "frontmatter",
        "game_agents",
        "insurance",
        "governance_bench",
        "harness_binding",
        "hooks",
        "loop",
        "mcp_client",
        "mcp_config",
        "mcp_admission",
        "session_replay",
        "step_compliance",
        "static_verify",
        "mcp_elicitation",
        "mcp_negotiate",
        "decision_model",
        "action_card",
        "multisig",
        "passport",
        "permissions",
        "plugin_load",
        "plugin_manifest",
        "policy_file",
        "postconditions",
        "offline_bundle",
        "process_receipts",
        "twin_receipts",
        "sports_agents",
    "defense_agents",
        "retail_agents",
        "dating_agents",
        "science_agents",
    "eldercare_agents",
    "proptech_agents",
        "newsmedia_agents",
    "support_agents",
        "finance_agents",
        "agrifood_agents",
        "transport_agents",
        "healthcare_agents",
        "education_agents",
        "quantum_timeline",
        "product_path",
        "provider_retry",
        "provenance_taint",
        "run_setup",
        "sdk",
        "scaffold",
        "sessions",
        "session_lease",
        "session_view",
        "session_ui",
        "sidecar_client",
        "skill_audit",
        "skill_check",
        "skills",
        "soc_verdicts",
        "stream_guard",
        "herd_gate",
        "housing",
        "deployment_registry",
        "scene_bound",
        "language_cap",
        "evaluator_access",
        "incident_receipts",
        "synthetic_cap",
        "dual_use",
        "editorial",
        "env_cost",
        "tracing",
        "vendor_chain",
        "safety_envelope",
        "audit_export",
        "akf_export",
        "audit_chain",
        "delegation_credentials",
        "audit_cli",
        "audit_rekor",
        "audit_archive",
        "audit_scitt",
        "hlc",
        "trace_export",
        "ed25519",
        "evidence_tiers",
        "tools.__init__",
        "tools.effect_envelope",
        "tools.os_sandbox",
        "tools.seccomp",
        "tools.capdrop",
        "tools.pledge",
        "tools.parallel",
        "tools.path_integrity",
        "tools.shell",
        "tools.skill_scripts",
        "tools.verify_invariants",
        "tools.fetch",
        "tools.sandbox",
        "audit_merkle",
        "dataflow_policy",
        "plugin_trust",
        "counterfactual",
        # The package's own module is the re-export surface embedders import from, so it
        # is documented rather than assumed.
        "providers.__init__",
        "providers.base",
        "providers.anthropic",
        "providers.openai_compat",
        "providers.scripted",
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
