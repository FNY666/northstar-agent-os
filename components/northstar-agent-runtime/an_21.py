"""an_21: title-case a string. Stdlib only."""

def title(s):
    return s.title()

if __name__ == "__main__":
    assert title('hello world') == 'Hello World'
    assert title('a') == 'A'
    print("ok")
