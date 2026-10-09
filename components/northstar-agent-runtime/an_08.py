"""an_08: check if even. Stdlib only."""

def is_even(x):
    return x % 2 == 0

if __name__ == "__main__":
    assert is_even(4)
    assert not is_even(5)
    print("ok")
