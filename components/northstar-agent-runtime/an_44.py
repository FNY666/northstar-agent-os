"""an_44: primes up to n. Stdlib only."""

def primes(n):
    out = []
    for i in range(2, n + 1):
        if all(i % p for p in out if p * p <= i):
            out.append(i)
    return out

if __name__ == "__main__":
    assert primes(10) == [2, 3, 5, 7]
    assert primes(1) == []
    print("ok")
