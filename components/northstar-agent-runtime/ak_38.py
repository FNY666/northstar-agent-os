"""ak_38: Primes up to n (sieve)."""

def primes_upto(n):
    sieve = [True] * (n + 1)
    sieve[:2] = [False, False]
    for i in range(2, int(n ** 0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = [False] * len(sieve[i*i::i])
    return [i for i, p in enumerate(sieve) if p]

if __name__ == '__main__':
    assert primes_upto(10) == [2, 3, 5, 7]
    assert primes_upto(1) == []
    print('ok')
