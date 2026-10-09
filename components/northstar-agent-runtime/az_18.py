"""Sum of digits. stdlib only."""

def digit_sum(n):
    return sum(int(d) for d in str(abs(n)))

def test():
    assert digit_sum(123) == 6
    assert digit_sum(0) == 0
    assert digit_sum(-45) == 9

if __name__ == '__main__':
    test(); print('ok')
