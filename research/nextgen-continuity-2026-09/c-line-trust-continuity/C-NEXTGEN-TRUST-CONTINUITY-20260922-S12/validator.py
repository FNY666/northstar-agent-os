#!/usr/bin/env python3
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
ALLOWED={"RECOVERED","UNKNOWN","REJECT"}
WINDOWS={"W0_before_journal","W1_after_journal_before_ack","W2_after_ack_before_replay","W3_during_replay","W4_after_replay_before_reconciliation","W5_during_reconciliation","W6_after_reconciliation"}
def main():
 p=ROOT/"outputs/results.json"; d=json.loads(p.read_text())
 assert d["synthetic_only"] is True and d["production_verified"] is False
 assert d["case_count"] == len(d["results"]) >= 12
 assert set(d["outcome_vocabulary"]) == ALLOWED
 for r in d["results"]:
  assert r["synthetic_only"] is True and r["production_verified"] is False
  assert r["outcome"] in ALLOWED and r["outcome"] == r["expected_outcome"]
  assert r["crash_window"] in WINDOWS
  if r["outcome"] == "UNKNOWN": assert r["unknown_preserved"] is True
  if r["outcome"] == "REJECT": assert r["unknown_preserved"] is False
 print(f"PASS: local results validator; {d['case_count']} results; UNKNOWN/REJECT separation verified")
if __name__=='__main__': main()
