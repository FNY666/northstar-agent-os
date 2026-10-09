"""Primality test. stdlib only."""

def is_prime(n):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0: return False
    i = 3
    while i * i <= n:
        if n % i == 0: return False
        i += 2
    return True

def test():
    assert is_prime(7)
    assert not is_prime(9)
    assert not is_prime(1)

if __name__ == '__main__':
    test(); print('ok')
