"""an_22: strip whitespace. Stdlib only."""

def strip(s):
    return s.strip()

if __name__ == "__main__":
    assert strip('  hi  ') == 'hi'
    assert strip('x') == 'x'
    print("ok")
