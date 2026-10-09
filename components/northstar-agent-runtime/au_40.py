"""au_40: Capitalize each word."""
def capitalize_words(s):
    """Capitalize the first letter of each word."""
    return ' '.join(w[:1].upper() + w[1:] for w in s.split(' '))

def _run_tests():
    assert capitalize_words('hello world') == 'Hello World'
    assert capitalize_words('') == ''

if __name__ == "__main__":
    _run_tests()
    print("au_40 OK")
