"""AJ-45: Confusion counts."""
from __future__ import annotations
VERSION = "aj_45.v1"


def confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    return tp, tn, fp, fn

def main() -> None:
    assert confusion([1,0,1,0],[1,1,0,0]) == (1,1,1,1)
    assert confusion([1],[1]) == (1,0,0,0)
    print(f"aj_45 OK")
if __name__ == "__main__": main()
