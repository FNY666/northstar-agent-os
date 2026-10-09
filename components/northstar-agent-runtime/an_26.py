"""an_26: split string into words. Stdlib only."""

def splitw(s):
    return s.split()

if __name__ == "__main__":
    assert splitw('a b c') == ['a', 'b', 'c']
    assert splitw('') == []
    print("ok")
