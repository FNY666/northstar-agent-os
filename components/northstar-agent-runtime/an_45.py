"""an_45: digital sum. Stdlib only."""

def dsum(n):
    return sum(int(d) for d in str(abs(n)))

if __name__ == "__main__":
    assert dsum(123) == 6
    assert dsum(-45) == 9
    print("ok")
