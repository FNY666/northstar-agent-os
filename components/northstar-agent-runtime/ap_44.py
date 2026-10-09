"""sieve utility."""

def sieve(n):
    if n < 2: return []
    s = [True]*(n+1); s[0]=s[1]=False
    for i in range(2, int(n**0.5)+1):
        if s[i]:
            s[i*i::i] = [False]*len(range(i*i, n+1, i))
    return [i for i, p in enumerate(s) if p]


def _self_test():
    assert sieve(10) == [2,3,5,7]
    assert sieve(1) == []


if __name__ == "__main__":
    _self_test()
    print("ap_44: OK")
