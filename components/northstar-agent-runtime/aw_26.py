"""Count whitespace-separated words."""
def count_words(s):
    return len(s.split())
if __name__ == "__main__":
    assert count_words("a b  c") == 3
    assert count_words("") == 0
    assert count_words(" one ") == 1
    print("ok")
