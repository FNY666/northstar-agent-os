"""ax_18: mode utility (stdlib only)."""
def mode(nums):
    from collections import Counter
    return Counter(nums).most_common(1)[0][0]


def run_tests():
    assert (mode([1,2,2,3])) == 2, 'mode([1,2,2,3])'
    assert (mode([5])) == 5, 'mode([5])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_18: ok")
