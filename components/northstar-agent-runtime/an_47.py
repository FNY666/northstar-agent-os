"""an_47: reverse digits of number. Stdlib only."""

def revnum(n):
    return int(str(abs(n))[::-1])

if __name__ == "__main__":
    assert revnum(123) == 321
    assert revnum(100) == 1
    print("ok")
