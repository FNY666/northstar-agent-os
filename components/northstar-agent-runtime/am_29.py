"""am_29: join_words utility (stdlib only)."""

def join_words(words):
    return ' '.join(words)

def _run_tests():
    assert join_words(['a', 'b']) == 'a b', 'am_29'
    assert join_words([]) == '', 'am_29'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_29: all tests passed")
