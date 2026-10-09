"""Tiny utility: aq_25."""

fib_upto = lambda n: _fib(n)

def _fib(n):
    a, b, r = 0, 1, []
    while a <= n:
        r.append(a)
        a, b = b, a + b
    return r

def self_test():
    assert fib_upto(10) == [0,1,1,2,3,5,8]
    assert fib_upto(0) == [0]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
