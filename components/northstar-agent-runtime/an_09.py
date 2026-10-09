"""an_09: check if odd. Stdlib only."""

def is_odd(x):
    return x % 2 == 1

if __name__ == "__main__":
    assert is_odd(5)
    assert not is_odd(4)
    print("ok")
