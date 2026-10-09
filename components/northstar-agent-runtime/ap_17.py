"""mean utility."""

def mean(nums):
    return sum(nums)/len(nums) if nums else 0.0


def _self_test():
    assert mean([1,2,3]) == 2.0
    assert mean([]) == 0.0


if __name__ == "__main__":
    _self_test()
    print("ap_17: OK")
