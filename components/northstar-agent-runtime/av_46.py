"""List of decimal digits of an int (most significant first)."""
def digits(n):
    return [int(d) for d in str(abs(n))]
if __name__ == "__main__":
    assert digits(123) == [1, 2, 3]
    assert digits(0) == [0]
    assert digits(-45) == [4, 5]
    print("ok")
