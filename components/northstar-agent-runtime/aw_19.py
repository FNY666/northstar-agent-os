"""All primes up to n inclusive."""
def sieve_upto(n):
    s = [True] * (n + 1)
    s[:2] = [False, False]
    for i in range(2, int(n ** 0.5) + 1):
        if s[i]:
            s[i*i::i] = [False] * len(s[i*i::i])
    return [i for i, p in enumerate(s) if p]
if __name__ == "__main__":
    assert sieve_upto(10) == [2,3,5,7]
    assert sieve_upto(2) == [2]
    assert sieve_upto(1) == []
    print("ok")
