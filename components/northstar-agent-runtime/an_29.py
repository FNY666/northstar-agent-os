"""an_29: check prefix. Stdlib only."""

def starts(s, p):
    return s.startswith(p)

if __name__ == "__main__":
    assert starts('hello', 'he')
    assert not starts('hello', 'lo')
    print("ok")
