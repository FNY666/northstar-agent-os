"""Tiny utility: aq_40."""

run_lengths = lambda xs: _rl(xs)

def _rl(xs):
    if not xs:
        return []
    r = [[xs[0], 1]]
    for x in xs[1:]:
        if x == r[-1][0]:
            r[-1][1] += 1
        else:
            r.append([x, 1])
    return [(v, c) for v, c in r]

def self_test():
    assert run_lengths([1,1,2]) == [(1,2),(2,1)]
    assert run_lengths([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
