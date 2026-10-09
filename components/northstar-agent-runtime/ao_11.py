"""ao_11: dedupe utility (stdlib only)."""

def dedupe(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen: seen.add(x); out.append(x)
    return out


def _self_test():
    assert dedupe([1, 2, 1, 3]) == [1, 2, 3], 'dedupe([1, 2, 1, 3]) == [1, 2, 3]'
    assert dedupe([]) == [], 'dedupe([]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
