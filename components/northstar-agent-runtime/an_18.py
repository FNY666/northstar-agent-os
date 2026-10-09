"""an_18: reverse a string. Stdlib only."""

def rev(s):
    return s[::-1]

if __name__ == "__main__":
    assert rev('abc') == 'cba'
    assert rev('') == ''
    print("ok")
