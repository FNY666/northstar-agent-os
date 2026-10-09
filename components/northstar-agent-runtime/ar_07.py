"""Tiny utility: ar_07 (is prime)."""

def is_prime(n):
    if n<2:return False
    i=2
    while i*i<=n:
        if n%i==0:return False
        i+=1
    return True

def self_test():
    assert is_prime(7)
    assert not is_prime(1)
    assert not is_prime(9)
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
