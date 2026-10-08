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
        "a2a_budget_combo", "a2a_gates", "a2abreak_probes", "ab_testing",
        "abac_engine", "abe_interface", "abstract_interp", "abuse_limits",
        "abuse_reporter", "account_recovery", "action_card", "action_verifier",
        "active_learning", "activity_worker", "adjudication", "adtech_agents",
        "adversarial_detector", "adversarial_robustness", "agb_smoke_corpus", "agent_files",
        "agent_identity", "agent_memory", "agent_readiness", "agents",
        "agri", "agrifood_agents", "ai_accident", "ai_accountability",
        "ai_accountability_auditing", "ai_accountability_certification", "ai_accountability_incident", "ai_accountability_mitigation",
        "ai_accountability_monitoring", "ai_accountability_remediation", "ai_accountability_risk", "ai_accountability_testing",
        "ai_accountability_threat", "ai_accountability_validation", "ai_accountability_verification", "ai_accountability_vulnerability",
        "ai_act", "ai_adversarial", "ai_alignment", "ai_assurance",
        "ai_attack", "ai_attestation", "ai_attribution", "ai_audit",
        "ai_benchmarking", "ai_bias", "ai_calibration", "ai_certification",
        "ai_charter", "ai_circuit", "ai_compliance", "ai_compliance_auditing",
        "ai_compliance_certification", "ai_compliance_incident", "ai_compliance_mitigation", "ai_compliance_monitoring",
        "ai_compliance_remediation", "ai_compliance_risk", "ai_compliance_testing", "ai_compliance_threat",
        "ai_compliance_validation", "ai_compliance_verification", "ai_compliance_vulnerability", "ai_concept",
        "ai_constitution", "ai_containment", "ai_contestability_auditing", "ai_contestability_certification",
        "ai_contestability_incident", "ai_contestability_mitigation", "ai_contestability_monitoring", "ai_contestability_remediation",
        "ai_contestability_risk", "ai_contestability_testing", "ai_contestability_threat", "ai_contestability_validation",
        "ai_contestability_verification", "ai_contestability_vulnerability", "ai_counterfactual", "ai_defense",
        "ai_detection", "ai_distillation", "ai_distribution_shift", "ai_ensemble",
        "ai_ethics", "ai_ethics_auditing", "ai_ethics_certification", "ai_ethics_incident",
        "ai_ethics_mitigation", "ai_ethics_monitoring", "ai_ethics_remediation", "ai_ethics_risk",
        "ai_ethics_testing", "ai_ethics_threat", "ai_ethics_validation", "ai_ethics_verification",
        "ai_ethics_vulnerability", "ai_evaluation", "ai_explainability", "ai_exploit",
        "ai_failure", "ai_fairness", "ai_fairness_auditing", "ai_fairness_certification",
        "ai_fairness_incident", "ai_fairness_mitigation", "ai_fairness_monitoring", "ai_fairness_remediation",
        "ai_fairness_risk", "ai_fairness_testing", "ai_fairness_threat", "ai_fairness_validation",
        "ai_fairness_verification", "ai_fairness_vulnerability", "ai_feature", "ai_fuzzing",
        "ai_gating", "ai_governance", "ai_harm", "ai_incident",
        "ai_interpretability", "ai_isolation", "ai_liability", "ai_mechanistic",
        "ai_mitigation", "ai_monitoring", "ai_ood_detection", "ai_oversight",
        "ai_oversight_auditing", "ai_oversight_certification", "ai_oversight_incident", "ai_oversight_mitigation",
        "ai_oversight_monitoring", "ai_oversight_remediation", "ai_oversight_risk", "ai_oversight_testing",
        "ai_oversight_threat", "ai_oversight_validation", "ai_oversight_verification", "ai_oversight_vulnerability",
        "ai_pentesting", "ai_perturbation", "ai_policy", "ai_prevention",
        "ai_principles", "ai_privacy", "ai_probing", "ai_pruning",
        "ai_quarantine", "ai_recourse", "ai_recovery", "ai_redress",
        "ai_redteaming", "ai_regulation", "ai_remediation", "ai_resilience",
        "ai_risk", "ai_robustness", "ai_robustness_auditing", "ai_robustness_certification",
        "ai_robustness_incident", "ai_robustness_mitigation", "ai_robustness_monitoring", "ai_robustness_remediation",
        "ai_robustness_risk", "ai_robustness_testing", "ai_robustness_threat", "ai_robustness_validation",
        "ai_robustness_verification", "ai_robustness_vulnerability", "ai_safety", "ai_safety_auditing",
        "ai_safety_certification", "ai_safety_incident", "ai_safety_mitigation", "ai_safety_monitoring",
        "ai_safety_remediation", "ai_safety_risk", "ai_safety_testing", "ai_safety_threat",
        "ai_safety_validation", "ai_safety_verification", "ai_safety_vulnerability", "ai_saliency",
        "ai_sandbox", "ai_security", "ai_standards", "ai_stress_testing",
        "ai_surveillance", "ai_testing", "ai_threat", "ai_throttling",
        "ai_traceability_auditing", "ai_traceability_certification", "ai_traceability_incident", "ai_traceability_mitigation",
        "ai_traceability_monitoring", "ai_traceability_remediation", "ai_traceability_risk", "ai_traceability_testing",
        "ai_traceability_threat", "ai_traceability_validation", "ai_traceability_verification", "ai_traceability_vulnerability",
        "ai_transparency", "ai_transparency_auditing", "ai_transparency_certification", "ai_transparency_incident",
        "ai_transparency_mitigation", "ai_transparency_monitoring", "ai_transparency_remediation", "ai_transparency_risk",
        "ai_transparency_testing", "ai_transparency_threat", "ai_transparency_validation", "ai_transparency_verification",
        "ai_transparency_vulnerability", "ai_uncertainty", "ai_validation", "ai_verification",
        "ai_visualization", "ai_vulnerability", "akf_export", "alert_manager",
        "aligned_ai", "alignment_eval", "aml_screener", "amplification",
        "amqp_broker", "analytics_tracker", "ansible_playbook", "anti_entropy",
        "api_analytics", "api_client_gen", "api_gateway", "api_versioning",
        "apikey_manager", "approval_chain", "approval_chain_time", "approval_sla",
        "approval_sla_time", "approver_separation", "artifact_publisher", "asi04_probes",
        "asi07_corpus", "asi08_probes", "asi09_probes", "assistance_game",
        "assurance", "attested_receipts", "attribution", "audio_processor",
        "audit_agents", "audit_archive", "audit_chain", "audit_cli",
        "audit_committee", "audit_compaction", "audit_export", "audit_management",
        "audit_merkle", "audit_rekor", "audit_scitt", "audit_shipper",
        "auth_dict", "automated_alignment", "backdoor", "backdoor_detection",
        "backdoor_detector", "backpressure", "backup_manager", "bandit_algorithm",
        "barcode_scanner", "batch_processing", "bcp", "bdd_interface",
        "benchmark", "benchmark_runner", "beneficial_ai", "bft_interface",
        "bilinear_accumulator", "billing_engine", "bloom_filter", "blue_green_deploy",
        "booking_agents", "bot_manager", "bpmn_engine", "btree_index",
        "budget", "budget_approval_combo", "budget_combo", "budget_token_bucket",
        "bug_bounty", "bulkhead", "bulkhead_pattern", "byzantine_agreement",
        "c2pa", "cache_aside", "cache_stampede", "cache_tier",
        "calendar_service", "canary_controller", "canonical_json", "capability_eval",
        "capability_reassembly", "capability_warrants", "cci_detector", "ccpa",
        "cd_deployer", "cdn_manager", "cep_engine", "cert_manager",
        "chain_of_thought", "change_data_capture", "changelog", "changelog_generator",
        "chaos_experiment", "checkpoints", "ci_pipeline", "circuit",
        "circuit_breaker", "cirl", "claimed_auth_corpus", "cli",
        "cmmc", "coap_server", "code_formatter", "code_signer",
        "column_store", "command_hooks", "commerce", "compaction",
        "compaction_approval_combo", "compaction_masking", "companionship", "compliance",
        "compliance_checker", "compliance_reports", "compute_budget", "confidential_compute",
        "confidential_vm", "config_management", "config_server", "conformity",
        "congestion_control", "connection_pool", "connector_sdk", "consensus_interface",
        "consent_manager", "consent_receipts", "consistent_hash", "consistent_hashing",
        "constitutional_ai", "constitutional_monitor", "construction_agents", "contacts_manager",
        "container_registry", "content_authenticity", "content_moderator", "context_window",
        "contract_bridge", "contract_tester", "control_testing", "controllable_ai",
        "cooperative_irl", "coppa", "corrigibility", "count_min_sketch",
        "coverage_reporter", "cqrs", "cqrs_pattern", "crdt_counter",
        "crdt_interface", "crdt_map", "crdt_set", "credential_detector",
        "crisis_management", "critique_model", "cron_scheduler", "crypto_agility",
        "csv_processor", "currency_converter", "custom_domains", "dag_scheduler",
        "dast_scanner", "data_catalog", "data_deletion", "data_exfiltration",
        "data_export", "data_extraction", "data_lineage", "data_pipeline",
        "data_poisoning_detector", "data_residency", "data_sync", "data_validation",
        "data_versioning", "dataflow_policy", "dataset_version", "datasheet",
        "dating_agents", "ddos_protection", "dead_letter", "dead_letter_queue",
        "debate", "debate_protocol", "debugger", "deception",
        "deception_detector", "deceptive_alignment", "decision_model", "decision_table",
        "deepfake_detection", "defense_agents", "delay_queue", "delegation_credentials",
        "deny_monotonicity", "dependency_resolver", "deployment_registry", "developer_portal",
        "device_manager", "differential_privacy", "disaster_agents", "disaster_recovery",
        "distributed_consensus", "distributed_lock", "dkg_interface", "dns_manager",
        "dns_resolver", "doc_converter", "doc_scanner", "docker_interface",
        "doctor", "document_store", "dp_accountant", "dp_interface",
        "dpo", "drift_probe", "dual_use", "durable_bridge",
        "ed25519", "edge_compute", "edge_gate", "edge_gate_ml",
        "edge_memory_combo", "editorial", "education_agents", "egress_client",
        "egress_enforcer", "egress_proxy", "eldercare_agents", "email_service",
        "embodied", "enclave_interface", "encryption_at_rest", "energybid_agents",
        "env_cost", "escrow_service", "ethics_review", "evaluation",
        "evaluation_harness", "evaluator_access", "evasion_corpus", "evasion_defense",
        "event_bridge", "event_catalog", "event_sourcing", "events",
        "evidence_tiers", "exactly_once", "excel_handler", "experiment_tracker",
        "experiment_tracking", "exploit_difficulty", "face_detector", "failure_budget_combo",
        "failure_bundle", "failure_detector", "fairness_eval", "fe_interface",
        "feature_engineering", "feature_flags", "feature_store", "feature_viz",
        "federated_attack_detector", "federated_learning", "fedramp", "few_shot_learning",
        "fhe", "fhe_interface", "fhe_wrapper", "finance_agents",
        "fingerprinting", "flag_service", "flag_targeting", "flow_control",
        "forensics", "forest_fish", "formal_verif", "forward_seal_ledger",
        "fragile_watermark", "fraud_detector", "frontmatter", "full_text_search",
        "fulltext_search", "fuzzer", "game_agents", "gdpr",
        "geocoder", "geofence_manager", "glba", "goal_misgeneralization",
        "gossip_protocol", "governance", "governance_bench", "governed_action_runner",
        "govservices_agents", "gpai", "graceful_shutdown", "gradient_hacking",
        "graph_database", "graph_db", "graphql_gateway", "grc",
        "greenwash", "grid_agents", "grpc_gateway", "grpc_interface",
        "gset", "harness_binding", "hash_chain", "health_checker",
        "healthcare_agents", "helm_chart", "herd_gate", "hinted_handoff",
        "hipaa", "hlc", "hoare_logic", "homomorphic_training",
        "hooks", "housing", "housing_ai_agents", "hr_agents",
        "hsm", "hsm_interface", "http_client", "human_oversight",
        "hybrid_crypto", "hyperloglog", "i18n_manager", "ida",
        "idempotency_manager", "idempotent_producer", "identity_approval_combo", "identity_disclosure",
        "image_captioner", "image_optimization", "image_processor", "impact_assessment",
        "inbox_pattern", "incident_manager", "incident_receipts", "incident_reporting",
        "incident_response", "index_manager", "ingress_controller", "injection_detector",
        "injection_probe", "inner_alignment", "instrumental_convergence", "insurance",
        "integration_hub", "interop_bridge", "interpretability", "interpretability_probe",
        "interruptibility", "invitation_manager", "invoice_generator", "irl",
        "iso27001", "iterated_amplification", "jailbreak", "jailbreak_defense",
        "job_queue", "job_scheduler", "jwt_handler", "k8s_operator",
        "key_derivation", "key_management", "key_rotation", "key_value_store",
        "kill_approval_combo", "kill_switch", "kill_switch_distributed", "kms_interface",
        "kyc_verifier", "labor_algo", "language_cap", "lb_health",
        "leader_election", "ledger", "legal_agents", "legal_hold",
        "license_checker", "licensing", "linter", "load_balancer",
        "load_generator", "load_tester", "location_tracker", "log_aggregator",
        "loop", "lsm_tree", "lww_register", "machine_ethics",
        "machine_unlearning", "mandate_credentials", "manufacturing_agents", "markdown_renderer",
        "masdrift_corpus", "materialized_view", "mcp_admission", "mcp_approval_combo",
        "mcp_client", "mcp_combo", "mcp_config", "mcp_drift_monitor",
        "mcp_elicitation", "mcp_negotiate", "mcp_pivoting_detector", "mcp_semantic_diff",
        "mechanistic", "media_forensics", "membership_inference", "membership_inference_detector",
        "memory", "memory_admission", "memory_bitemporal", "memory_budget_combo",
        "memory_capability", "memory_combo", "memory_fact_belief", "memory_flat_vs_graph",
        "memory_safety", "merkle_tree", "mesa_optimization", "message_broker",
        "message_queue", "message_signing", "mfa_manager", "migration_runner",
        "mining_agents", "ml_model_registry", "model_card", "model_checker",
        "model_extraction_detector", "model_inversion", "model_lineage", "model_monitoring",
        "model_registry", "model_serving", "model_theft", "model_watermark",
        "model_watermarking", "moderation_agents", "mpc", "mpc_interface",
        "mqtt_broker", "multi_agent", "multi_tenancy", "multisig",
        "mutation_tester", "mvcc_store", "nats_server", "newsmedia_agents",
        "nist_csf", "no_token_monitor", "notes_manager", "notification_hub",
        "notified_body", "oauth2_provider", "object_detector", "observer_verdict_ledger",
        "ocr_engine", "offline_bundle", "oidc_provider", "oncall_scheduler",
        "orbital_agents", "org_manager", "origin_shield", "otel_tracer",
        "outbox_pattern", "outcome_supervision", "outer_alignment", "output_parser",
        "oversight_board", "oversight_evasion", "package_manager", "partition_manager",
        "passport", "password_hash", "password_policy", "paxos_acceptor",
        "paxos_interface", "payment_processor", "payout_engine", "pci_dss",
        "pdf_generator", "pen_testing", "per_call_budget", "permissions",
        "permit_agents", "personalization", "pharma_agents", "phi_detector",
        "plan_defense", "planner_budget_combo", "planner_gates", "planning_module",
        "plugin_load", "plugin_manifest", "plugin_trust", "pn_counter",
        "pocketos_probe", "poi_search", "poisoning_defense", "policy_engine",
        "policy_file", "policy_management", "poly_commitment", "post_dispatch_monitor",
        "postconditions", "power_seeking", "pqc_kem", "pqc_sig",
        "preference_learning", "priority_queue", "private_inference", "probe_defense_combo",
        "probe_flywheel", "probing", "process_receipts", "process_supervision",
        "procurement_agents", "product_path", "profiler", "prom_metrics",
        "prompt_injection", "prompt_stealing_detector", "prompt_template", "proof_assistant",
        "property_tester", "proptech_agents", "provenance", "provenance_attestor",
        "provenance_tagging", "provenance_taint", "provider_retry", "providers.__init__",
        "providers.anthropic", "providers.base", "providers.openai_compat", "providers.scripted",
        "pubsub_broker", "pulsar_broker", "push_service", "quantum_timeline",
        "query_planner", "raft_interface", "raft_log", "rag_pipeline",
        "rate_adapter", "rate_limiter", "rate_limiting", "rbac_engine",
        "read_repair", "read_through_cache", "recommendation_engine", "recursive_reward",
        "red_team", "red_teaming", "redis_pubsub", "reflection",
        "refusal_monitor", "regulatory", "relational_db", "release_manager",
        "remote_attestation", "replica_manager", "resource_accumulation", "responsible_ai",
        "retail_agents", "retry_policy", "reverse_proxy", "reward_hacking",
        "reward_modeling", "richtext_ot", "ring_sig", "risk_assessment",
        "risk_management", "rlaif", "rlhf", "roboethics",
        "robust_watermark", "robustness_eval", "robustness_testing", "routing_engine",
        "rsa_accumulator", "rule_engine", "rule_of_two_probe", "rum_monitor",
        "run_setup", "sae_interface", "safe_ai", "safety_case",
        "safety_envelope", "safety_eval", "safr_checkpoint", "saga_pattern",
        "saml_provider", "sandbagging", "sast_scanner", "sat_solver",
        "savepoint_manager", "sbom_generator", "scaffold", "scalable_oversight",
        "scalable_oversight_v2", "scene_bound", "schema_registry", "scheming",
        "science_agents", "scim_provisioning", "sdk", "sdk_generation",
        "seal_merkle_batch", "sealed_attestation", "sealed_audit_sink", "sealed_pipeline",
        "search_engine", "search_index", "secret_manager", "secret_scanner",
        "secret_sharing", "secrets_rotation", "secure_aggregation", "secure_enclave",
        "secure_inference", "seed_manager", "self_critique", "self_preservation",
        "separation_logic", "service_discovery", "service_mesh", "session_lease",
        "session_manager", "session_replay", "session_ui", "session_view",
        "sessions", "shutdown", "shutdownability", "sidecar_client",
        "siem", "signed_receipt_reflux", "silent_profiling_detector", "situational_awareness",
        "skill_audit", "skill_budget_combo", "skill_check", "skill_scanner",
        "skill_wiring", "skills", "sleeper_agent", "sleeper_eval",
        "slo_tracker", "sloppy_quorum", "sms_service", "smt_solver",
        "snapshot_isolation", "snapshot_tester", "soar", "soc",
        "soc2", "soc_verdicts", "sox", "spam_detector",
        "sparse_merkle", "specification_gaming", "speech_to_text", "split_learning",
        "sports_agents", "spotlighting", "sse_interface", "sse_manager",
        "sso_integration", "standards", "stark_hash", "state_backend",
        "state_machine", "static_verify", "steganography", "step_compliance",
        "stomp_broker", "stream_guard", "stream_join", "stream_processing",
        "streaming_sql", "structured_log", "subscription_manager", "superalignment",
        "supplychain_agents", "support_agents", "swim_protocol", "sycophancy",
        "sycophancy_detector", "symbolic_exec", "synthetic_cap", "synthetic_media",
        "synthetic_monitor", "system_card", "systemic_risk", "t_digest",
        "task_manager", "task_queue", "task_router", "tax_agents",
        "tax_calculator", "team_manager", "telecom_agents", "template_engine",
        "temporal_decoupling_probe", "temporal_logic", "tenant_billing", "tenant_quotas",
        "terraform_provider", "test_runner", "text_to_speech", "threat_hunting",
        "threat_intel", "three_phase_commit", "threshold_sig", "tile_server",
        "time_series_db", "timelock_enc", "timeout_management", "timeout_manager",
        "timeseries_db", "timezone_resolver", "tls_terminator", "token_counter",
        "tool_use", "tools.__init__", "tools.capdrop", "tools.effect_envelope",
        "tools.fetch", "tools.os_sandbox", "tools.parallel", "tools.path_integrity",
        "tools.pledge", "tools.sandbox", "tools.seccomp", "tools.shell",
        "tools.skill_scripts", "tools.verify_invariants", "trace_export", "traceability_paradox",
        "tracing", "traffic_steering", "transaction_manager", "transactional_messaging",
        "transparency", "transparency_log", "transport_agents", "treacherous_turn",
        "tripwire_guardrails", "trojan", "trojan_defense", "trust_safety",
        "trustworthy_ai", "twin_receipts", "two_phase_commit", "twopset",
        "type_checker", "type_checker_iface", "underwriting_agents", "user_profile",
        "validator_scarcity", "value_learning", "vdf_interface", "vector_clock",
        "vector_commitment", "vector_db", "vector_search", "vendor_chain",
        "vendor_risk", "verification_badges", "verkle_tree", "version_manager",
        "video_analyzer", "video_streaming", "video_transcoder", "virtual_nodes",
        "vr_interface", "vrf_interface", "vuln_disclosure", "vuln_scanner",
        "waf_rules", "waste_agents", "water_agents", "watermark",
        "watermark_tracker", "watermark_verifier", "weak_to_strong", "weak_to_strong_v2",
        "weather_service", "webhook_delivery", "webhook_dispatcher", "webhook_manager",
        "websocket_gateway", "websocket_manager", "white_label", "wireheading",
        "witness_enc", "workflow_automation", "workflow_engine", "workflow_orchestration",
        "write_ahead_log", "write_through_cache", "zab_interface", "zero_knowledge",
        "zeromq_patterns", "zk_interface", "zk_verifier",
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
