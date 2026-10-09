"""Log Softmax Util (AI-U-049), Simulated."""
from __future__ import annotations
VERSION = "ai_49.v1"

def log_softmax(xs):
    import math
    m = max(xs)
    ls = math.log(sum(math.exp(x - m) for x in xs)) + m
    return [x - ls for x in xs]

def main() -> None:
    import math
    x = log_softmax([1, 2])
    assert abs(math.exp(x[0]) + math.exp(x[1]) - 1.0) < 1e-9
    assert log_softmax([3])[0] == 0.0
    print(f"ai_49 OK")
if __name__ == "__main__": main()
