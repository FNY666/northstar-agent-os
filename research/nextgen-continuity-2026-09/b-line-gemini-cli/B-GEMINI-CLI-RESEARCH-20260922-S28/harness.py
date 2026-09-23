# synthetic_only=true; production_verified=false
#!/usr/bin/env python3
"""Offline deterministic retry/reconciliation permutation harness."""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"

def classify(case):
    s = case["scenario"]
    # Synthetic oracle: only a complete, matching transaction is accepted.
    if s == "valid_match":
        return "accepted", "reference and response match"
    if s == "response_mismatch":
        return "rejected", "response differs from reference"
    # These paths deliberately do not assert a production outcome.
    return "UNKNOWN", {"missing_response": "response unavailable", "invalid_reference": "reference unavailable"}[s]

def main():
    suite = json.loads(CASES.read_text())
    rows = []
    for c in suite["cases"]:
        verdict, reason = classify(c)
        rows.append({**c, "verdict": verdict, "reason": reason,
                     "synthetic_only": True, "production_verified": False})
    result = {"synthetic_only": True, "production_verified": False,
              "suite_id": suite["suite_id"], "worker_id": suite["worker_id"],
              "op_id": suite["op_id"], "case_count": len(rows), "results": rows}
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    counts = {k: sum(r["verdict"] == k for r in rows) for k in ("accepted", "rejected", "UNKNOWN")}
    print(json.dumps({"case_count": len(rows), "counts": counts,
                      "sha256": hashlib.sha256(OUT.read_bytes()).hexdigest()}, sort_keys=True))

if __name__ == "__main__":
    main()
