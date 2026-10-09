"""Tiny utility: ar_10 (palindrome check)."""

def is_pal(s):
    t=''.join(c.lower() for c in s if c.isalnum())
    return t==t[::-1]

def self_test():
    assert is_pal('A man, a plan, a canal: Panama')
    assert not is_pal('hello')
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
