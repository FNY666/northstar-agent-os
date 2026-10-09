"""xor_all utility."""

def xor_all(nums):
    r = 0
    for n in nums:
        r ^= n
    return r


def _self_test():
    assert xor_all([1,2,3,2,1]) == 3
    assert xor_all([]) == 0


if __name__ == "__main__":
    _self_test()
    print("ap_34: OK")
