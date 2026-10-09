"""median utility."""

def median(nums):
    s = sorted(nums)
    n = len(s)
    if not n: return 0.0
    m = n//2
    return (s[m-1]+s[m])/2 if n%2==0 else s[m]


def _self_test():
    assert median([3,1,2]) == 2
    assert median([1,2,3,4]) == 2.5


if __name__ == "__main__":
    _self_test()
    print("ap_18: OK")
