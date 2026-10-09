"""Tiny utility: ar_08 (factorial)."""

def fact(n):
    r=1
    for i in range(2,n+1):r*=i
    return r

def self_test():
    assert fact(5)==120
    assert fact(0)==1
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
