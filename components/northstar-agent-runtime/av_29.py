"""Min-max scale numbers into [0, 1]."""
def minmax_scale(nums):
    nums = list(nums)
    lo, hi = min(nums), max(nums)
    if hi == lo:
        return [0.0] * len(nums)
    return [(x - lo) / (hi - lo) for x in nums]
if __name__ == "__main__":
    assert minmax_scale([1, 2, 3]) == [0.0, 0.5, 1.0]
    assert minmax_scale([7, 7]) == [0.0, 0.0]
    assert minmax_scale([-1, 1]) == [0.0, 1.0]
    print("ok")
