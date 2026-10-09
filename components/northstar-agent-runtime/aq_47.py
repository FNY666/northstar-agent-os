"""Tiny utility: aq_47."""

title_case = lambda s: ' '.join(w.capitalize() for w in s.split())

def self_test():
    assert title_case('hello world') == 'Hello World'
    assert title_case('') == ''
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
