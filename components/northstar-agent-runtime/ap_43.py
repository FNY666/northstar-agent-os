"""factorize utility."""

def factorize(n):
    f, d = {}, 2
    while d*d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0)+1; n //= d
        d += 1
    if n > 1: f[n] = f.get(n, 0)+1
    return f


def _self_test():
    assert factorize(12) == {2:2, 3:1}
    assert factorize(7) == {7:1}


if __name__ == "__main__":
    _self_test()
    print("ap_43: OK")
