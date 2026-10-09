"""Sieve of Eratosthenes. stdlib only."""

def primes_upto(n):
    sieve = [True] * (n+1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(n**0.5)+1):
        if sieve[i]:
            for j in range(i*i, n+1, i):
                sieve[j] = False
    return [i for i, p in enumerate(sieve) if p]

def test():
    assert primes_upto(10) == [2,3,5,7]
    assert primes_upto(2) == [2]
    assert primes_upto(1) == []

if __name__ == '__main__':
    test(); print('ok')
