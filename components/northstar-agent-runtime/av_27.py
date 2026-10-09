"""Simple moving average with window k."""
def moving_average(nums, k):
    nums = list(nums)
    if k <= 0 or k > len(nums):
        raise ValueError("bad window")
    return [sum(nums[i:i + k]) / k for i in range(len(nums) - k + 1)]
if __name__ == "__main__":
    assert moving_average([1, 2, 3, 4], 2) == [1.5, 2.5, 3.5]
    assert moving_average([5, 5], 2) == [5.0]
    assert moving_average([1, 2, 3], 1) == [1.0, 2.0, 3.0]
    print("ok")
