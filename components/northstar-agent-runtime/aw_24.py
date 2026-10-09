"""True if string reads the same backwards."""
def palindrome(s):
    return s == s[::-1]
if __name__ == "__main__":
    assert palindrome("racecar") is True
    assert palindrome("hello") is False
    assert palindrome("") is True
    print("ok")
