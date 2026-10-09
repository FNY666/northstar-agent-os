"""Arithmetic mean of numbers."""
def mean(nums):
    nums = list(nums)
    if not nums:
        raise ValueError("empty")
    return sum(nums) / len(nums)
if __name__ == "__main__":
    assert mean([1, 2, 3, 4]) == 2.5
    assert mean([5]) == 5.0
    try:
        mean([])
        raise AssertionError("no raise")
    except ValueError:
        pass
    print("ok")
