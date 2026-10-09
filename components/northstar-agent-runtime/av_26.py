"""Character n-grams of a string."""
def ngrams(text, n):
    return [text[i:i + n] for i in range(len(text) - n + 1)]
if __name__ == "__main__":
    assert ngrams("abcd", 2) == ["ab", "bc", "cd"]
    assert ngrams("ab", 3) == []
    assert ngrams("aaa", 1) == ["a", "a", "a"]
    print("ok")
