"""Prime factorization as list (with multiplicity)."""
def prime_factors(n):
    out, p = [], 2
    while p * p <= n:
        while n % p == 0:
            out.append(p); n //= p
        p += 1
    if n > 1:
        out.append(n)
    return out
if __name__ == "__main__":
    assert prime_factors(12) == [2,2,3]
    assert prime_factors(13) == [13]
    assert prime_factors(1) == []
    print("ok")
