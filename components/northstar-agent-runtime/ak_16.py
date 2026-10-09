"""ak_16: Prime check."""

def is_prime(n):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0: return False
        i += 2
    return True

if __name__ == '__main__':
    assert is_prime(17)
    assert not is_prime(15)
    assert not is_prime(1)
    print('ok')
