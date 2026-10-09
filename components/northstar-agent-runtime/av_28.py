"""Z-score normalize a list of numbers."""
import math
def zscore(nums):
    nums = list(nums)
    m = sum(nums) / len(nums)
    sd = math.sqrt(sum((x - m) ** 2 for x in nums) / len(nums))
    if sd == 0:
        return [0.0] * len(nums)
    return [(x - m) / sd for x in nums]
if __name__ == "__main__":
    assert zscore([5, 5, 5]) == [0.0, 0.0, 0.0]
    zs = zscore([1, 2, 3])
    assert abs(zs[1]) < 1e-9
    assert abs(sum(zs)) < 1e-9
    print("ok")
