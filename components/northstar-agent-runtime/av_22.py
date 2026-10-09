"""Check if text is a palindrome (ignoring case/punct)."""
import re
def is_palindrome(text):
    s = re.sub(r"[^a-z0-9]", "", text.lower())
    return s == s[::-1]
if __name__ == "__main__":
    assert is_palindrome("A man, a plan, a canal: Panama") is True
    assert is_palindrome("hello") is False
    assert is_palindrome("") is True
    print("ok")
