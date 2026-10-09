"""Conf Threshold Util (AI-U-050), Simulated."""
from __future__ import annotations
VERSION = "ai_50.v1"

def conf_pass(scores, thresh):
    return [s >= thresh for s in scores]

def main() -> None:
    assert conf_pass([0.9, 0.2, 0.7], 0.5) == [True, False, True]
    assert conf_pass([], 0.1) == []
    print(f"ai_50 OK")
if __name__ == "__main__": main()
