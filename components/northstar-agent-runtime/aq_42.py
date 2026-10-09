"""Tiny utility: aq_42."""

word_freq = lambda s: {w: s.split().count(w) for w in set(s.split())}

def self_test():
    assert word_freq('a b a') == {'a':2,'b':1}
    assert word_freq('') == {}
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
