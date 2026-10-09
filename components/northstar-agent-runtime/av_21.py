"""Reverse word order in a string."""
def reverse_words(text):
    return " ".join(reversed(text.split()))
if __name__ == "__main__":
    assert reverse_words("a b c") == "c b a"
    assert reverse_words("one") == "one"
    assert reverse_words("") == ""
    print("ok")
