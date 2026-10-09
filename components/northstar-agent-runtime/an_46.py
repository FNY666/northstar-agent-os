"""an_46: count digits. Stdlib only."""

def ndigits(n):
    return len(str(abs(n)))

if __name__ == "__main__":
    assert ndigits(12345) == 5
    assert ndigits(0) == 1
    print("ok")
