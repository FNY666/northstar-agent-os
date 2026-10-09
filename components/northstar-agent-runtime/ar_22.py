"""Tiny utility: ar_22 (truncate)."""

def truncate(s,n,suffix='...'):
    return s if len(s)<=n else s[:n-len(suffix)]+suffix

def self_test():
    assert truncate('hello',10)=='hello'
    assert truncate('hello world',8)=='hello...'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
