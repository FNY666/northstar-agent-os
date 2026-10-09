"""ak_06: GCD and LCM helpers."""

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
def lcm(a, b):
    return a * b // gcd(a, b)

if __name__ == '__main__':
    assert gcd(12, 18) == 6
    assert lcm(4, 6) == 12
    assert gcd(7, 13) == 1
    print('ok')
