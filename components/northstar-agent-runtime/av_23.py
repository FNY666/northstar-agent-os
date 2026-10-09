"""Strip punctuation characters from a string."""
import string
def strip_punct(text):
    return text.translate(str.maketrans("", "", string.punctuation))
if __name__ == "__main__":
    assert strip_punct("hi! you?") == "hi you"
    assert strip_punct("...") == ""
    assert strip_punct("plain") == "plain"
    print("ok")
