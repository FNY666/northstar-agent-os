"""ak_40: Roman numeral to int."""

def roman(s):
    v = {'I': 1, 'V': 5, 'X': 10, 'L': 50, 'C': 100, 'D': 500, 'M': 1000}
    t, prev = 0, 0
    for c in reversed(s.upper()):
        cur = v[c]
        t += cur if cur >= prev else -cur
        prev = cur
    return t

if __name__ == '__main__':
    assert roman('XIV') == 14
    assert roman('MMXXIV') == 2024
    print('ok')
