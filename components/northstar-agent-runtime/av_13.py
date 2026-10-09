"""Mode (most frequent value; first wins ties)."""
from collections import Counter
def mode(nums):
    c = Counter(nums)
    if not c:
        raise ValueError("empty")
    return max(c, key=lambda k: (c[k], -list(nums).index(k)))
if __name__ == "__main__":
    assert mode([1, 2, 2, 3]) == 2
    assert mode([5]) == 5
    assert mode([1, 1, 2, 2]) == 1
    print("ok")
