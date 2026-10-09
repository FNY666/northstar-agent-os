"""an_36: last element. Stdlib only."""

def last(xs):
    return xs[-1]

if __name__ == "__main__":
    assert last([9, 8]) == 8
    assert last(['a']) == 'a'
    print("ok")
