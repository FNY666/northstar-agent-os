"""Tiny utility: ar_21 (slugify)."""

def slugify(s):
    import re
    return re.sub(r'[^a-z0-9]+','-',s.lower()).strip('-')

def self_test():
    assert slugify('Hello World!')=='hello-world'
    assert slugify('  A  B ')== 'a-b'
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
