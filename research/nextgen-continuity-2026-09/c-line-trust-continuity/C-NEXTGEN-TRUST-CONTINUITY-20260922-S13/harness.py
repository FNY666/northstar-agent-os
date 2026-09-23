#!/usr/bin/env python3
"""Offline deterministic synthetic evidence-provenance model; no I/O beyond local JSON."""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIX = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"


def evaluate(case, config):
    budget = case.get("budget", config["observation_budget"])
    obs = case.get("observations", [])
    consumed = obs[:max(0, budget)]
    budget_exhausted = len(obs) > len(consumed)
    provenance = []
    for index, item in enumerate(obs):
        entry = dict(item)
        entry["input_index"] = index
        entry["considered"] = index < len(consumed)
        entry["fresh"] = item.get("freshness_age_seconds") is not None and item["freshness_age_seconds"] <= config["freshness_window_seconds"]
        entry["accessible"] = bool(item.get("accessible", False))
        entry["usable"] = entry["considered"] and entry["accessible"] and entry["fresh"]
        entry["observation_role"] = "evidence" if entry["usable"] else ("unavailable" if not entry["accessible"] else "excluded")
        provenance.append(entry)

    usable = [x for x in provenance if x["usable"]]
    grouped = {}
    for item in usable:
        key = (item.get("event_id"), item.get("seq"))
        grouped.setdefault(key, []).append(item)
    conflict_groups = []
    recovered_groups = []
    for key, items in sorted(grouped.items(), key=lambda pair: str(pair[0])):
        decisions = {x.get("decision") for x in items}
        sources = {x.get("source_id") for x in items}
        if len(decisions) > 1 and len(sources) >= 2:
            conflict_groups.append({"event_id": key[0], "seq": key[1], "source_ids": sorted(sources), "decisions": sorted(decisions), "input_indices": [x["input_index"] for x in items]})
        if decisions == {"RECOVERED"} and len(sources) >= 2:
            recovered_groups.append({"event_id": key[0], "seq": key[1], "source_ids": sorted(sources), "input_indices": [x["input_index"] for x in items]})

    if conflict_groups:
        status = "REJECT"
        reason = "explicit fresh same-version contradictory terminal decisions from independent sources"
    elif recovered_groups:
        status = "RECOVERED"
        reason = "at least two independent accessible fresh observations agree on the same event version"
    else:
        status = "UNKNOWN"
        reasons = []
        if not obs: reasons.append("missing observations")
        if obs and not usable: reasons.append("no usable accessible fresh observations within budget")
        if usable and not recovered_groups: reasons.append("insufficient independent agreeing observations")
        if budget_exhausted: reasons.append("observation budget exhausted before all supplied records were considered")
        if any(not x["accessible"] for x in provenance): reasons.append("one or more provenance records inaccessible")
        if any(x["accessible"] and not x["fresh"] for x in provenance): reasons.append("one or more accessible records stale")
        reason = "; ".join(dict.fromkeys(reasons)) or "no recovery or explicit contradiction rule matched"
    return {
        "case_id": case["id"], "status": status, "reason": reason,
        "budget": budget, "consumed_observations": len(consumed), "supplied_observations": len(obs),
        "budget_exhausted": budget_exhausted, "recovery_groups": recovered_groups,
        "conflict_groups": conflict_groups, "provenance": provenance,
        "synthetic_only": True, "production_verified": False
    }


def main():
    data = json.loads(FIX.read_text(encoding="utf-8"))
    results = [evaluate(c, data["model_config"]) for c in data["cases"]]
    payload = {"schema_version": "S13-results-1.0", "synthetic_only": True, "production_verified": False, "model_config": data["model_config"], "results": results}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: evaluated {len(results)} synthetic cases")
    for r in results: print(f"{r['case_id']}: {r['status']}")

if __name__ == "__main__":
    main()
