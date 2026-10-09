"""AJ-46: Accuracy."""
from __future__ import annotations
VERSION = "aj_46.v1"


def accuracy(y_true, y_pred):
    return sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true)

def main() -> None:
    assert accuracy([1,0,1],[1,0,0]) == 2/3
    assert accuracy([1],[1]) == 1.0
    print(f"aj_46 OK")
if __name__ == "__main__": main()
