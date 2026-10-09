"""Population variance of numbers."""
def variance(nums):
    nums = list(nums)
    if not nums:
        raise ValueError("empty")
    m = sum(nums) / len(nums)
    return sum((x - m) ** 2 for x in nums) / len(nums)
if __name__ == "__main__":
    assert variance([2, 4, 4, 4, 5, 5, 7, 9]) == 4.0
    assert variance([3, 3, 3]) == 0.0
    assert variance([1, 3]) == 1.0
    print("ok")
