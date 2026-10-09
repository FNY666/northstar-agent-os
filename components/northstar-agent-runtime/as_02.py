"""capitalize_words utility."""

def capitalize_words(s):
    return ' '.join(w[:1].upper() + w[1:] for w in s.split())


def _selftest():
    assert capitalize_words("hello world") == "Hello World"
    assert capitalize_words("") == ""


if __name__ == "__main__":
    _selftest()
    print("ok")
