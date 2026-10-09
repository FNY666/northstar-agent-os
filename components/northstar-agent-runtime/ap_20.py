"""running_sum utility."""

def running_sum(nums):
    out, t = [], 0
    for n in nums:
        t += n; out.append(t)
    return out


def _self_test():
    assert running_sum([1,2,3]) == [1,3,6]
    assert running_sum([]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_20: OK")
