"""Tiny utility: aq_22."""

lcm_two = lambda a, b: abs(a*b)//__import__('math').gcd(a,b) if a and b else 0

def self_test():
    assert lcm_two(4,6) == 12
    assert lcm_two(0,5) == 0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
