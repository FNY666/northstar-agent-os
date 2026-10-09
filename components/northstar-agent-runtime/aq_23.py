"""Tiny utility: aq_23."""

prime_factors = lambda n: _pf(n)

def _pf(n):
    r = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            r.append(d)
            n //= d
        d += 1
    if n > 1:
        r.append(n)
    return r

def self_test():
    assert prime_factors(12) == [2,2,3]
    assert prime_factors(13) == [13]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
