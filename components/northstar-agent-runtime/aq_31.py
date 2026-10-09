"""Tiny utility: aq_31."""

collatz_steps = lambda n: _c(n, 0)

def _c(n, s):
    return s if n == 1 else _c(n//2 if n % 2 == 0 else 3*n+1, s+1)

def self_test():
    assert collatz_steps(1) == 0
    assert collatz_steps(6) == 8
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
