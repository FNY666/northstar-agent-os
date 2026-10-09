"""an_35: first element. Stdlib only."""

def first(xs):
    return xs[0]

if __name__ == "__main__":
    assert first([9, 8]) == 9
    assert first(['a']) == 'a'
    print("ok")
