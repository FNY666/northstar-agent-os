"""ax_16: mean utility (stdlib only)."""
def mean(nums):
    if not nums: raise ValueError('empty')
    return sum(nums) / len(nums)


def run_tests():
    assert (mean([1,2,3])) == 2.0, 'mean([1,2,3])'
    assert (mean([5])) == 5.0, 'mean([5])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_16: ok")
