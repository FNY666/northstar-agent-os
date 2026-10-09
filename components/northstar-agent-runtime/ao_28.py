"""ao_28: from_roman utility (stdlib only)."""

def from_roman(s):
    v = {'I':1,'V':5,'X':10,'L':50,'C':100,'D':500,'M':1000}
    total = prev = 0
    for c in reversed(s):
        cur = v[c]; total += cur if cur >= prev else -cur; prev = cur
    return total


def _self_test():
    assert from_roman('IV') == 4, "from_roman('IV') == 4"
    assert from_roman('MCMXCIV') == 1994, "from_roman('MCMXCIV') == 1994"


if __name__ == "__main__":
    _self_test()
    print("ok")
