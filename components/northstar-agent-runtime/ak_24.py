"""ak_24: Sum of digits."""

def digit_sum(n):
    return sum(int(d) for d in str(abs(n)))

if __name__ == '__main__':
    assert digit_sum(123) == 6
    assert digit_sum(-45) == 9
    print('ok')
