"""an_10: clamp value into [lo, hi]. Stdlib only."""

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

if __name__ == "__main__":
    assert clamp(5, 0, 3) == 3
    assert clamp(-1, 0, 3) == 0
    print("ok")
