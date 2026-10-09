"""an_25: join words with space. Stdlib only."""

def joinw(words):
    return ' '.join(words)

if __name__ == "__main__":
    assert joinw(['a', 'b']) == 'a b'
    assert joinw([]) == ''
    print("ok")
