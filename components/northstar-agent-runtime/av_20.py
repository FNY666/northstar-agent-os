"""Count words in a string."""
def word_count(text):
    return len(text.split())
if __name__ == "__main__":
    assert word_count("hello world") == 2
    assert word_count("  one   two  ") == 2
    assert word_count("") == 0
    print("ok")
