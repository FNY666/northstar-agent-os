"""an_19: uppercase a string. Stdlib only."""

def up(s):
    return s.upper()

if __name__ == "__main__":
    assert up('abc') == 'ABC'
    assert up('aBc') == 'ABC'
    print("ok")
