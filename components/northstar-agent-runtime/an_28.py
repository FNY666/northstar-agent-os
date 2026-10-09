"""an_28: replace substring. Stdlib only."""

def repl(s, old, new):
    return s.replace(old, new)

if __name__ == "__main__":
    assert repl('aaa', 'a', 'b') == 'bbb'
    assert repl('hi', 'z', 'q') == 'hi'
    print("ok")
