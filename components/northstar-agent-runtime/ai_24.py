"""Confusion Counts Util (AI-U-024), Simulated."""
from __future__ import annotations
VERSION = "ai_24.v1"

def confusion(preds, labels):
    return {'tp': sum(p == l == 1 for p, l in zip(preds, labels)), 'fp': sum(p == 1 and l == 0 for p, l in zip(preds, labels)), 'fn': sum(p == 0 and l == 1 for p, l in zip(preds, labels)), 'tn': sum(p == l == 0 for p, l in zip(preds, labels))}

def main() -> None:
    c = confusion([1, 1, 0, 0], [1, 0, 1, 0])
    assert c == {'tp': 1, 'fp': 1, 'fn': 1, 'tn': 1}
    assert confusion([1, 0], [1, 0]) == {'tp': 1, 'fp': 0, 'fn': 0, 'tn': 1}
    print(f"ai_24 OK")
if __name__ == "__main__": main()
