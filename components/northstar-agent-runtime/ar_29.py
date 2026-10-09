"""Tiny utility: ar_29 (word frequency)."""

def word_freq(s):
    d={}
    for w in s.lower().split():d[w]=d.get(w,0)+1
    return d

def self_test():
    assert word_freq('a b a')=={'a':2,'b':1}
    assert word_freq('')=={}
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
