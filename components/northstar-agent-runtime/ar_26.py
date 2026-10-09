"""Tiny utility: ar_26 (run length decode)."""

def unrle(pairs):
    return ''.join(c*n for c,n in pairs)

def self_test():
    assert unrle([('a',3),('b',2)])=='aaabb'
    assert unrle([])==''
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
