#!/usr/bin/env python3
"""Synthetic, offline-only admission-gate policy probe.

This tests decision ordering, not any real authority, service, registry, target,
clock, or secret. It intentionally never performs I/O beyond stdout.
"""
from __future__ import annotations
import json
from copy import deepcopy

REQUIRED = (
    "authority", "producer_auth", "target_binding", "registry_cas",
    "readback", "fencing", "trusted_time", "secret_boundary",
    "append_only_audit", "rollback_reconcile",
)


def decide(case):
    # Schema validation is a prerequisite, but never a production trust root.
    if case.get("schema") != "verified":
        return {"decision": "NO_GO", "reason": "schema_not_verified"}
    if case.get("requested_mode") == "schema-only":
        return {"decision": "CONDITIONAL_GO_SCHEMA_ONLY", "reason": "pure_schema_only"}
    if case.get("d1_opt_in") != "verified":
        return {"decision": "NO_GO", "reason": "d1_opt_in_required"}
    missing = [k for k in REQUIRED if case.get(k) != "verified"]
    if missing:
        return {"decision": "NO_GO", "reason": "trust_gate_missing_or_unknown", "missing": missing}
    if case.get("requested_mode") == "controlled-dry-run":
        return {"decision": "ELIGIBLE_CONTROLLED_DRY_RUN", "reason": "all_preflight_gates_closed"}
    # Even complete preflight evidence is not a production approval. A separate
    # target-specific authorization and observed end-to-end acceptance are needed.
    if case.get("target_specific_authorization") != "verified":
        return {"decision": "NO_GO", "reason": "target_specific_authorization_missing"}
    if case.get("real_external_acceptance") != "verified":
        return {"decision": "NO_GO", "reason": "real_external_acceptance_unverified"}
    return {"decision": "REAL_GO", "reason": "explicit_target_acceptance_and_all_gates"}


def run():
    base = {"schema": "verified", "d1_opt_in": "verified"}
    cases = []
    cases.append(("schema-only", {**base, "requested_mode": "schema-only"}))
    cases.append(("d1-missing", {**base, "requested_mode": "controlled-dry-run", "d1_opt_in": "unknown"}))
    full = {**base, "requested_mode": "controlled-dry-run"}
    for gate in REQUIRED:
        full[gate] = "verified"
    cases.append(("all-preflight-dry-run", full))
    blocked = deepcopy(full); blocked["authority"] = "unknown"
    cases.append(("authority-unknown", blocked))
    real = {**full, "requested_mode": "real", "target_specific_authorization": "verified"}
    cases.append(("real-acceptance-missing", real))
    real_ok = {**real, "real_external_acceptance": "verified"}
    cases.append(("synthetic-real-all-flags", real_ok))
    out = []
    for name, case in cases:
        result = decide(case)
        out.append({"case": name, **result})
    print(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2))
    expected = {
        "schema-only": "CONDITIONAL_GO_SCHEMA_ONLY",
        "d1-missing": "NO_GO",
        "all-preflight-dry-run": "ELIGIBLE_CONTROLLED_DRY_RUN",
        "authority-unknown": "NO_GO",
        "real-acceptance-missing": "NO_GO",
        "synthetic-real-all-flags": "REAL_GO",
    }
    got = {x["case"]: x["decision"] for x in out}
    assert got == expected
    assert all(x["decision"] != "REAL_GO" for x in out if x["case"] != "synthetic-real-all-flags")


if __name__ == "__main__":
    run()
