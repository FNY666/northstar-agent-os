"""Sum of integers in [lo, hi] inclusive."""
def range_sum(lo, hi):
    return (hi - lo + 1) * (lo + hi) // 2
if __name__ == "__main__":
    assert range_sum(1, 10) == 55
    assert range_sum(5, 5) == 5
    assert range_sum(-3, 3) == 0
    print("ok")
