"""Tiny utility: aq_41."""

compress = lambda s: ''.join(f'{v}{c}' for v, c in run_lengths(s)) if False else ''.join(f'{x}{sum(1 for _ in g)}' for x, g in __import__('itertools').groupby(s))

def self_test():
    assert compress('aab') == 'a2b1'
    assert compress('') == ''
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
