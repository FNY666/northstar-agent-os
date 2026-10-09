"""an_27: repeat string n times. Stdlib only."""

def rep(s, n):
    return s * n

if __name__ == "__main__":
    assert rep('ab', 3) == 'ababab'
    assert rep('x', 0) == ''
    print("ok")
