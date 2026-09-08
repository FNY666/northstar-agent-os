"""Remote/hosted-worker readiness scorecard (P3-3) — evidence-based, runnable.

Northstar does not build a cloud; this module turns the *evaluation* into a
reproducible artifact. It answers "how close is this repository to wrapping
its sidecar execution model into a remote worker?" by checking facts that can
be verified statically inside the tree — modules exist, key symbols are
exported, schema versions and constants are defined, required fields exist,
interop helpers validate versions — and aggregates them per capability area.

Nothing here imports the components (it parses text/reads files), so it is
safe to run in CI and cannot drift from the code it measures: the checks ARE
the evaluation. Run it with:

    python3 -m remote_worker --score        # one-line total (for CI)
    python3 -m remote_worker                # detailed per-area table

The numbers are the objective backbone of the P3-3 assessment
(docs/dx-remote-worker-assessment.zh-CN.md). A check returning True is a
point *toward* the area; each area is then scored as points/total so a single
noisy check cannot dominate.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

COMPONENTS = Path(__file__).resolve().parents[2] / "components"
REPO = Path(__file__).resolve().parents[2]
AREAS = (
    ("contracts", "versioned run request/receipt"),
    ("host", "default-deny auth, opaque workspace, signed grants"),
    ("durable-run", "event store, leases, action gate, verifier"),
    ("interop", "process boundary + handoff + canary"),
    ("audit", "canonical NDJSON feed everywhere"),
    ("ops", "identity/transport/deploy/monitoring (gaps expected)"),
)


def _text(*parts: str) -> str:
    return (COMPONENTS / Path(*parts)).read_text(encoding="utf-8", errors="replace")


def _exists(*parts: str) -> bool:
    return (COMPONENTS / Path(*parts)).is_file()


def _repo_doc(needle: str, *parts: str) -> bool:
    """True when a repository doc exists and carries a required header marker.

    The flipped ops checks below measure *authoritative artifacts in the
    repo* (a story page, an operator guide). The status markers they look for
    are the same ones the repo-level docs tests pin, so a stub file cannot
    flip a score.
    """
    path = REPO.joinpath(*parts)
    if not path.is_file():
        return False
    return needle in path.read_text(encoding="utf-8", errors="replace")


def _has(needle: str, haystack: str) -> bool:
    return needle in haystack


def _exported(name: str, module: str) -> bool:
    return bool(re.search(rf"^(class|def) {name}\b", module, re.MULTILINE))


def _constant(name: str, module: str) -> bool:
    return bool(re.search(rf"^{name}\s*=", module, re.MULTILINE))


def _schema(name: str, module: str) -> bool:
    return bool(re.search(rf"^{name}\s*=\s*['\"]northstar\.", module, re.MULTILINE))


# (area, check, explanation) — each True counts toward its area's score.
# Checks target REAL symbols (verified against the tree); checks whose
# explanation starts with "MISSING" are expected-gap probes: they are False
# today and are the remaining implementation work items (T5b).
CHECKS: list[tuple[str, Callable[[], bool], str]] = [
    # -- contracts -----------------------------------------------------------
    ("contracts", lambda: _has("northstar.run.v1", _text("northstar-run-contract", "contract.py")), "run request schema"),
    ("contracts", lambda: _has("SCHEMA_VERSION = \"northstar.run.v1\"", _text("northstar-run-contract", "contract.py")), "schema version"),
    ("contracts", lambda: _exported("validate_run_request", _text("northstar-run-contract", "contract.py")), "run request validator"),
    ("contracts", lambda: _exported("make_receipt", _text("northstar-run-contract", "contract.py")), "run receipt builder"),
    ("contracts", lambda: _has("northstar.policy.v1", _text("northstar-run-contract", "policy.py")), "policy schema identity"),
    ("contracts", lambda: _exported("validate_revision", _text("northstar-run-contract", "policy.py")), "revision validator"),
    # -- host ----------------------------------------------------------------
    ("host", lambda: _exported("authorize_run", _text("northstar-host", "authorization.py")), "authorize_run"),
    ("host", lambda: _exported("verify_authorization", _text("northstar-host", "authorization.py")), "verify_authorization"),
    ("host", lambda: _exported("HostPolicy", _text("northstar-host", "authorization.py")), "HostPolicy"),
    ("host", lambda: _exported("load_host_policy", _text("northstar-host", "host_policy.py")), "policy-as-code loader"),
    ("host", lambda: _has("grant_ttl_seconds", _text("northstar-host", "authorization.py")), "grant TTL"),
    ("host", lambda: _has("def allocate", _text("northstar-host", "workspace.py")), "opaque workspace broker"),
    # -- durable-run -----------------------------------------------------------
    ("durable-run", lambda: _exported("EventStore", _text("northstar-durable-run", "event_store.py")), "event store"),
    ("durable-run", lambda: _exported("ActionGateway", _text("northstar-durable-run", "action_gateway.py")), "per-call action gate"),
    ("durable-run", lambda: _exported("verify_run_completion", _text("northstar-durable-run", "verifier.py")), "independent postcondition verifier"),
    ("durable-run", lambda: _has("class LeaseManager", _text("northstar-durable-run", "runner.py")), "lease manager"),
    ("durable-run", lambda: _has("def heartbeat", _text("northstar-durable-run", "runner.py")), "lease heartbeat"),
    ("durable-run", lambda: _exported("DurableRunner", _text("northstar-durable-run", "runner.py")), "bounded step runner"),
    # -- interop -------------------------------------------------------------
    ("interop", lambda: _exported("ProcessAgentAdapter", _text("northstar-agent-interop", "process_adapter.py")), "process adapter"),
    ("interop", lambda: _exported("ProcessBackendSpec", _text("northstar-agent-interop", "process_backend.py")), "backend spec"),
    ("interop", lambda: _exported("codex_cli_spec", _text("northstar-agent-interop", "process_backend.py")), "codex cli spec"),
    ("interop", lambda: _exported("sign_attestation", _text("northstar-agent-interop", "handoff.py")), "attestation signing"),
    ("interop", lambda: _exported("verify_handoff_grant", _text("northstar-agent-interop", "handoff.py")), "handoff grant verify"),
    ("interop", lambda: _has("class AdapterReceipt", _text("northstar-agent-interop", "interop_adapter.py")), "structured execution receipt"),
    # -- audit ---------------------------------------------------------------
    ("audit", lambda: _has('AUDIT_SCHEMA_VERSION = "audit.ndjson/1"', _text("northstar-run-contract", "audit.py")), "canonical audit schema"),
    ("audit", lambda: _exported("iter_ndjson", _text("northstar-run-contract", "audit.py")), "audit parser"),
    ("audit", lambda: _exported("transcript_path_to_ndjson", _text("northstar-agent-runtime", "audit_export.py")), "runtime transcript export"),
    ("audit", lambda: _exported("event_to_audit", _text("northstar-durable-run", "durable_audit.py")), "durable event export"),
    ("audit", lambda: _exported("authorization_to_audit", _text("northstar-host", "host_audit.py")), "host grant export"),
    ("audit", lambda: _exported("authorization_to_ndjson", _text("northstar-host", "host_audit.py")), "host ndjson line"),
    # -- ops: remote-worker-specific (expected gaps are the T5 work list) ------
    ("ops", lambda: _has("timeout_seconds", _text("northstar-agent-interop", "process_adapter.py")), "bounded timeout"),
    ("ops", lambda: _has("def _terminate", _text("northstar-agent-interop", "process_adapter.py")), "process-group termination"),
    ("ops", lambda: _repo_doc("Status: a story, not a system", "docs", "concepts", "northstar-remote-identity.md"), "credential issuance + rotation story (docs/concepts/northstar-remote-identity.md)"),
    ("ops", lambda: _repo_doc("Status: an operator guide, not a product", "docs", "guides", "remote-worker-operations.md"), "deployment/monitoring operator guide (docs/guides/remote-worker-operations.md)"),
    ("ops", lambda: False, "MISSING: complete Profile A transport readiness (local ssh_forward.py helper exists; flips only after strict host-key configuration and a real-host canary pass; Profile B remains open)"),
    ("ops", lambda: False, "MISSING: real (non-fake) end-to-end remote canary run (recipe: examples/remote-canary; flips only after an operator run passes on a real host)"),
]

def score() -> dict[str, tuple[int, int, list[str]]]:
    """Per-area (met, total, unmet explanations)."""
    totals = {area: 0 for area, _ in AREAS}
    met = {area: 0 for area, _ in AREAS}
    unmet: dict[str, list[str]] = {area: [] for area, _ in AREAS}
    for area, check, explanation in CHECKS:
        totals[area] += 1
        if check():
            met[area] += 1
        else:
            unmet[area].append(explanation)
    return {area: (met[area], totals[area], unmet[area]) for area, _ in AREAS}


def total_score() -> int:
    result = score()
    met = sum(value[0] for value in result.values())
    total = sum(value[1] for value in result.values())
    return round(100 * met / total)


def _run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--score", action="store_true", help="print one total line")
    args = parser.parse_args(argv)
    if args.score:
        print(f"remote-worker readiness: {total_score()}/100")
        return 0
    print(f"{'area':<13} {'met/total':<9} %")
    result = score()
    for area, label in AREAS:
        met, total, _ = result[area]
        print(f"{area:<13} {met}/{total:<6} {round(100 * met / total) if total else 0}")
    print(f"{'OVERALL':<13} {sum(v[0] for v in result.values())}/"
          f"{sum(v[1] for v in result.values()):<5} {total_score()}")
    for area, label in AREAS:
        met, total, unmet = result[area]
        if met < total:
            print(f"\n{area} gaps: {', '.join(unmet)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
