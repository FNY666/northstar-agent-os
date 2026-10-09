"""Population standard deviation."""
import math
def stddev(nums):
    nums = list(nums)
    if not nums:
        raise ValueError("empty")
    m = sum(nums) / len(nums)
    return math.sqrt(sum((x - m) ** 2 for x in nums) / len(nums))
if __name__ == "__main__":
    assert stddev([2, 4, 4, 4, 5, 5, 7, 9]) == 2.0
    assert stddev([5, 5]) == 0.0
    assert abs(stddev([1, 2, 3]) - 0.8164965) < 1e-6
    print("ok")
