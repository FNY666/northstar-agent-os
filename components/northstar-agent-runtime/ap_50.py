"""percentile utility."""

def percentile(nums, p):
    if not nums: return 0.0
    s = sorted(nums); k = (len(s)-1)*p/100
    f = int(k); c = f+1
    return s[f] if c >= len(s) else s[f]+(s[c]-s[f])*(k-f)


def _self_test():
    assert percentile([1,2,3,4], 50) == 2.5
    assert percentile([], 50) == 0.0


if __name__ == "__main__":
    _self_test()
    print("ap_50: OK")
