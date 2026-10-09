"""ak_09: Fibonacci generator."""

def fibs(n):
    a, b, out = 0, 1, []
    for _ in range(n):
        out.append(a); a, b = b, a + b
    return out

if __name__ == '__main__':
    assert fibs(6) == [0, 1, 1, 2, 3, 5]
    assert fibs(0) == []
    print('ok')
