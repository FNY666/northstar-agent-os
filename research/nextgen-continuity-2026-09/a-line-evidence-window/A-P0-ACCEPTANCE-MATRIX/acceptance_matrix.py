#!/usr/bin/env python3
import hashlib, itertools, json

ITEMS = {
    1: ("contract_explicit_reject", "E1", "schema/contract rejects malformed or unauthorized shape"),
    2: ("target_postcondition", "E3", "independent target readback proves postcondition"),
    3: ("effect_state", "E3", "authoritative effect state readback matches expected"),
    4: ("target_mismatch", "E1", "target fingerprint mismatch is explicitly rejected"),
    5: ("sent_no_response", "E2", "send without response remains unknown"),
    6: ("audit_only", "E2", "audit receipt alone cannot prove business effect"),
    7: ("resource_state", "E3", "resource readback proves intended state"),
    8: ("downstream_state", "E3", "downstream readback proves propagated effect"),
    9: ("rollback_coverage", "E1", "rollback plan is complete and mechanically checked"),
    10: ("artifact_hash", "E2", "artifact hash binds bytes, not semantics or runtime use"),
}

def classify(item, evidence):
    name, tier, _ = ITEMS[item]
    if item in (1, 4, 9):
        return "VERIFIED" if evidence.get(name) is True else "NO_GO"
    if item in (2, 3, 7, 8):
        return "VERIFIED" if evidence.get(name) is True and evidence.get("independent_readback") is True else "UNKNOWN"
    if item in (5, 6):
        return "UNKNOWN"
    if item == 10:
        return "CONDITIONAL" if evidence.get(name) is True else "UNKNOWN"
    raise AssertionError(item)

# 2^10 fixture matrix, with hard invariants for every evidence combination.
rows = []
keys = [v[0] for v in ITEMS.values()]
for bits in itertools.product((False, True), repeat=len(keys)):
    ev = dict(zip(keys, bits))
    ev["independent_readback"] = False
    rows.append({"evidence": ev, "verdicts": {str(i): classify(i, ev) for i in ITEMS}})

assert len(rows) == 1024
for row in rows:
    v = row["verdicts"]
    assert v["5"] == "UNKNOWN" and v["6"] == "UNKNOWN"
    assert v["2"] == "UNKNOWN" and v["3"] == "UNKNOWN" and v["7"] == "UNKNOWN" and v["8"] == "UNKNOWN"
    assert v["10"] in ("CONDITIONAL", "UNKNOWN")

# Positive/negative acceptance cases.
all_e3 = {k: True for k in keys}; all_e3["independent_readback"] = True
positive = {str(i): classify(i, all_e3) for i in ITEMS}
assert positive["2"] == positive["3"] == positive["7"] == positive["8"] == "VERIFIED"
assert positive["1"] == positive["4"] == positive["9"] == "VERIFIED"
negative = dict(all_e3); negative["target_postcondition"] = False
assert classify(2, negative) == "UNKNOWN"

out = {
    "items": len(ITEMS), "combinations": len(rows),
    "evidence_tiers": {"E1": "direct contract/negative proof", "E2": "platform/audit/request evidence", "E3": "independent external readback/postcondition"},
    "positive_case": positive, "negative_readback_case": {"item_2": classify(2, negative)},
    "invariants": "PASS", "real_production_acceptance": "NO_GO_UNTIL_E3_AND_D1_AND_TRUST_GATES"
}
print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
