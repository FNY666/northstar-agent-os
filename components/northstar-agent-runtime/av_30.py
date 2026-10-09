"""Cumulative sums of a sequence."""
def cumsum(nums):
    out, total = [], 0
    for x in nums:
        total += x
        out.append(total)
    return out
if __name__ == "__main__":
    assert cumsum([1, 2, 3]) == [1, 3, 6]
    assert cumsum([]) == []
    assert cumsum([-1, 1]) == [-1, 0]
    print("ok")
