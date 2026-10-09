"""an_23: count characters in a string. Stdlib only."""

def charcount(s):
    return len(s)

if __name__ == "__main__":
    assert charcount('hello') == 5
    assert charcount('') == 0
    print("ok")
