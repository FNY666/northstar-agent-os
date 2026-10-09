"""an_20: lowercase a string. Stdlib only."""

def low(s):
    return s.lower()

if __name__ == "__main__":
    assert low('ABC') == 'abc'
    assert low('aBc') == 'abc'
    print("ok")
