"""au_41: Remove punctuation."""
import string
def strip_punct(s):
    """Remove ASCII punctuation from s."""
    return s.translate(str.maketrans('', '', string.punctuation))

def _run_tests():
    assert strip_punct('a,b!c') == 'abc'
    assert strip_punct('ok') == 'ok'

if __name__ == "__main__":
    _run_tests()
    print("au_41 OK")
