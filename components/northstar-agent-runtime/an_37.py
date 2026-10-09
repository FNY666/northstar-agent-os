"""an_37: list length. Stdlib only."""

def llen(xs):
    return len(xs)

if __name__ == "__main__":
    assert llen([1, 2]) == 2
    assert llen([]) == 0
    print("ok")
