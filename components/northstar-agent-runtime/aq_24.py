"""Tiny utility: aq_24."""

is_prime = lambda n: n > 1 and all(n % i for i in range(2, int(n**0.5)+1))

def self_test():
    assert is_prime(7)
    assert not is_prime(9)
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
