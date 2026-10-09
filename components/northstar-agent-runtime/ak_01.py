"""ak_01: Clamp a value into a range."""

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

if __name__ == '__main__':
    assert clamp(5, 0, 10) == 5
    assert clamp(-3, 0, 10) == 0
    assert clamp(42, 0, 10) == 10
    print('ok')
