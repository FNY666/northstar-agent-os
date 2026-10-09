"""Tiny utility: aq_46."""

reverse_words = lambda s: ' '.join(s.split()[::-1])

def self_test():
    assert reverse_words('a b c') == 'c b a'
    assert reverse_words('x') == 'x'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
