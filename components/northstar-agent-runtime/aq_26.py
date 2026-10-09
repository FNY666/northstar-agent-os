"""Tiny utility: aq_26."""

factorial = lambda n: 1 if n < 2 else n * factorial(n-1)

def self_test():
    assert factorial(5) == 120
    assert factorial(0) == 1
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
