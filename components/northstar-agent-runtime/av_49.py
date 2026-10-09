"""Repeat/truncate a string to exactly length n."""
def repeat_to(s, n):
    if n <= 0:
        return ""
    return (s * ((n // len(s)) + 1))[:n]
if __name__ == "__main__":
    assert repeat_to("ab", 5) == "ababa"
    assert repeat_to("abc", 2) == "ab"
    assert repeat_to("x", 0) == ""
    print("ok")
