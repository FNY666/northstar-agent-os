"""ax_19: range_of utility (stdlib only)."""
def range_of(nums):
    return max(nums) - min(nums)


def run_tests():
    assert (range_of([1,5,3])) == 4, 'range_of([1,5,3])'
    assert (range_of([7])) == 0, 'range_of([7])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_19: ok")
