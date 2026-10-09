"""an_24: check palindrome. Stdlib only."""

def is_pal(s):
    return s == s[::-1]

if __name__ == "__main__":
    assert is_pal('racecar')
    assert not is_pal('hello')
    print("ok")
