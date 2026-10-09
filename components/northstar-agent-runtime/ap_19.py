"""mode utility."""

def mode(nums):
    return max(set(nums), key=nums.count) if nums else None


def _self_test():
    assert mode([1,2,2,3]) == 2
    assert mode([]) is None


if __name__ == "__main__":
    _self_test()
    print("ap_19: OK")
