"""Truncate a string to at most n chars with ellipsis."""
def truncate(text, n, ellipsis="..."):
    if len(text) <= n:
        return text
    return text[: max(0, n - len(ellipsis))] + ellipsis
if __name__ == "__main__":
    assert truncate("hello world", 8) == "hello..."
    assert truncate("hi", 8) == "hi"
    assert truncate("abcdef", 6) == "abcdef"
    print("ok")
