"""Longest word; first wins ties."""
def longest_word(s):
    ws = s.split()
    return max(ws, key=len) if ws else ""
if __name__ == "__main__":
    assert longest_word("a bb ccc dd") == "ccc"
    assert longest_word("") == ""
    assert longest_word("aa bb") == "aa"
    print("ok")
