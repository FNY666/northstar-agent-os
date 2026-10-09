"""Tiny utility: ar_09 (fibonacci)."""

def fib(n):
    a,b=0,1
    for _ in range(n):a,b=b,a+b
    return a

def self_test():
    assert fib(10)==55
    assert fib(0)==0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
