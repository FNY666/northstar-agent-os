"""ak_32: Power-of-two check."""

def is_power_of_two(n):
    return isinstance(n, int) and n > 0 and (n & (n - 1)) == 0

if __name__ == '__main__':
    assert is_power_of_two(16)
    assert not is_power_of_two(15)
    assert not is_power_of_two(0)
    print('ok')
