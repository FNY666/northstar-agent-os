"""True if strings are anagrams."""
def anagram(a, b):
    return sorted(a) == sorted(b)
if __name__ == "__main__":
    assert anagram("listen", "silent") is True
    assert anagram("abc", "abd") is False
    assert anagram("", "") is True
    print("ok")
