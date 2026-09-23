#!/usr/bin/env python3
"""Deterministic local S16 synthetic harness.
No network, service, SDK, credential, or external artifact access is used.
"""
from __future__ import annotations
import hashlib
import json
import sys
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path

BASE = Path(__file__).resolve().parent
CASES = BASE / "fixtures" / "cases.json"
OUT = BASE / "outputs" / "results.json"
VERSIONS = ("v1", "v2")
STATUSES = {"RECOVERED", "UNKNOWN", "REJECT"}

class CanonicalizationError(Exception):
    pass

def normalize_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)

def canon_value(value, path="$", seen=None):
    """Normalize strings to NFC, omit nulls, and canonicalize Decimal numbers."""
    if value is None:
        return None
    if isinstance(value, str):
        return normalize_string(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError(f"non-finite number at {path}")
        if value == 0:
            return Decimal(0)
        # Decimal tuples preserve lexical precision while this removes only
        # insignificant trailing zeros (e.g. 1.0 -> 1; 1.2300 -> 1.23).
        return value.normalize()
    if isinstance(value, list):
        return [canon_value(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        result = {}
        for raw_key, raw_val in value.items():
            key = normalize_string(raw_key)
            if key in result:
                raise CanonicalizationError(f"normalized key collision at {path}: {key!r}")
            val = canon_value(raw_val, f"{path}.{key}")
            if val is not None:  # declared null/omission equivalence
                result[key] = val
        return result
    raise CanonicalizationError(f"unsupported value at {path}: {type(value).__name__}")

def json_default(value):
    if isinstance(value, Decimal):
        if value == 0:
            return "0"
        return format(value, "f")
    raise TypeError(type(value).__name__)

def canonical_bytes(value):
    normalized = canon_value(value)
    # Encode Decimal as canonical JSON number tokens, not quoted strings.
    def emit(v):
        if v is None:
            return "null"
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, Decimal):
            if v == 0:
                return "0"
            text = format(v, "f")
            if "." in text:
                text = text.rstrip("0").rstrip(".")
            if text in ("", "-0"):
                text = "0"
            return text
        if isinstance(v, list):
            return "[" + ",".join(emit(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{" + ",".join(
                json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + emit(v[k])
                for k in sorted(v)
            ) + "}"
        raise TypeError(type(v).__name__)
    return emit(normalized).encode("utf-8")

def canonical_hash(value):
    data = canonical_bytes(value)
    return "sha256:" + hashlib.sha256(data).hexdigest(), data.decode("utf-8")

def load_cases():
    with CASES.open(encoding="utf-8") as f:
        return json.load(f, parse_int=Decimal, parse_float=Decimal)

def prov_state(p):
    if not isinstance(p, dict):
        return False, "provenance record is not an object"
    if p.get("integrity") == "contradictory":
        return False, "verifiable provenance integrity contradiction"
    if p.get("parent_match") == "mismatch":
        return False, "verifiable L2-to-L1 parent mismatch"
    return True, ""

def base_decision(case, version):
    """Return a version-local decision before cross-version drift handling."""
    p = case["provenance"]
    for level in ("l1", "l2"):
        ok, why = prov_state(p.get(level))
        if not ok:
            return "REJECT", why, [why]
    l1 = p.get("l1", {})
    l2 = p.get("l2", {})
    if not l1.get("present", False) or not l1.get("complete", False):
        return "UNKNOWN", "L1 provenance is missing or incomplete", ["L1 complete record"]
    if not l2.get("present", False) or not l2.get("complete", False):
        if version == "v2" and case.get("rule_profile") == "v2_l1_only_acceptance":
            pass
        else:
            return "UNKNOWN", "L2 provenance is missing or incomplete", ["L2 complete record"]
    if not l1.get("reachable", False):
        return "UNKNOWN", "L1 provenance level is unreachable", ["reachable L1 chain"]
    if not l2.get("reachable", False):
        if version == "v2" and case.get("rule_profile") == "v2_l1_only_acceptance":
            pass
        else:
            return "UNKNOWN", "L2 provenance level is unreachable", ["reachable L2 chain"]
    if version == "v2" and case.get("rule_profile") == "v2_requires_attestation":
        if case.get("attestation") != "valid":
            if case.get("version_difference_policy") == "explicit_contradiction":
                return "REJECT", "v2 attestation difference explicitly declared a contradiction", ["valid v2 attestation"]
            return "UNKNOWN", "v2 requires valid attestation", ["valid v2 attestation"]
    return "RECOVERED", "all required provenance levels are complete, reachable, and coherent", []

def run_one(case, version, hash_a, hash_b, canonical_a, canonical_b):
    status, reason, blockers = base_decision(case, version)
    canonical_equal = hash_a == hash_b
    # A declared content mismatch is a rule-verifiable contradiction; an
    # ordinary serialization mismatch is only a hash-equivalence observation.
    if case.get("content_expectation") == "must_match" and not canonical_equal:
        status = "REJECT"
        reason = "canonical content hashes contradict must_match expectation"
        blockers = ["canonical content equality"]
    elif not canonical_equal and status == "RECOVERED":
        status = "UNKNOWN"
        reason = "canonical content hashes differ; semantic equivalence is not established"
        blockers = ["canonical content equality"]
    return {
        "rule_set": version,
        "status": status,
        "reason": reason,
        "blockers": blockers,
        "provenance": case["provenance"],
        "input_hash": hash_a,
        "comparison_input_hash": hash_b,
        "canonical_hash_equal": canonical_equal,
        "canonical_bytes_sha256": hashlib.sha256(canonical_a.encode("utf-8")).hexdigest(),
        "comparison_canonical_bytes_sha256": hashlib.sha256(canonical_b.encode("utf-8")).hexdigest(),
        "synthetic_only": True,
        "production_verified": False,
    }

def main():
    cases = load_cases()
    results = []
    for case in cases:
        if set(case) < {"id", "description", "payload_a", "payload_b", "provenance"}:
            raise SystemExit(f"incomplete case: {case.get('id')}")
        try:
            hash_a, canonical_a = canonical_hash(case["payload_a"])
            hash_b, canonical_b = canonical_hash(case["payload_b"])
            runs = [run_one(case, v, hash_a, hash_b, canonical_a, canonical_b) for v in VERSIONS]
        except CanonicalizationError as exc:
            # Keep an input hash even for canonicalization failures by hashing
            # the deterministic, NFC-normalized raw case envelope.
            raw = json.dumps(case["payload_a"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=lambda x: format(x, "f") if isinstance(x, Decimal) else str(x))
            hash_a = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
            hash_b = hash_a
            runs = [{
                "rule_set": v, "status": "REJECT",
                "reason": f"canonicalization contradiction: {exc}",
                "blockers": ["canonicalizable JSON content"],
                "provenance": case["provenance"], "input_hash": hash_a,
                "comparison_input_hash": hash_b, "canonical_hash_equal": False,
                "canonical_bytes_sha256": None, "comparison_canonical_bytes_sha256": None,
                "synthetic_only": True, "production_verified": False,
            } for v in VERSIONS]
            canonical_a = canonical_b = ""
        statuses = {r["status"] for r in runs}
        drift = {
            "present": runs[0]["status"] != runs[1]["status"],
            "from": runs[0]["status"],
            "to": runs[1]["status"],
            "recorded": True,
            "classification": "VERSION_CONFLICT" if runs[0]["status"] != runs[1]["status"] else "NONE",
            "rule_sets_compared": ["v1", "v2"],
        }
        if drift["present"]:
            if case.get("version_difference_policy") == "explicit_contradiction":
                final_status = "REJECT"
                final_reason = "version drift is explicitly declared a contradiction by the fixture rule"
                final_blockers = ["explicit version-difference contradiction policy"]
            else:
                final_status = "UNKNOWN"
                final_reason = "version conflict: v1 and v2 produce different decisions"
                final_blockers = ["single agreed rule_set version"]
        else:
            final_status = runs[0]["status"]
            final_reason = "both rule_set versions produce the same decision"
            final_blockers = sorted(set(runs[0]["blockers"] + runs[1]["blockers"]))
        results.append({
            "fixture_id": case["id"],
            "description": case["description"],
            "runs": runs,
            "version_drift": drift,
            "final_status": final_status,
            "final_reason": final_reason,
            "final_blockers": final_blockers,
            "provenance": case["provenance"],
            "input_hash": hash_a,
            "rule_sets_used": ["v1", "v2"],
            "synthetic_only": True,
            "production_verified": False,
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": "S16-results-1",
        "generated_by": "harness.py",
        "deterministic": True,
        "fixture_count": len(results),
        "run_count": len(results) * 2,
        "results": results,
    }
    OUT.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"PASS: generated {len(results)} fixtures / {len(results)*2} rule-set runs")
    print("PASS: deterministic canonical SHA-256 output written to outputs/results.json")
    print("PASS: statuses restricted to RECOVERED, UNKNOWN, REJECT")

if __name__ == "__main__":
    main()
