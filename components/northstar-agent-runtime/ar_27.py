"""Tiny utility: ar_27 (balanced parens)."""

def balanced(s):
    d=0
    for c in s:
        if c=='(':d+=1
        elif c==')':
            d-=1
            if d<0:return False
    return d==0

def self_test():
    assert balanced('(a(b)c)')
    assert not balanced('(()')
    assert balanced('')
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
