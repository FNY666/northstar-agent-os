"""Count vowels (aeiou, case-insensitive) in a string."""
def count_vowels(text):
    return sum(1 for ch in text.lower() if ch in "aeiou")
if __name__ == "__main__":
    assert count_vowels("hello") == 2
    assert count_vowels("xyz") == 0
    assert count_vowels("AEIOU") == 5
    print("ok")
