"""unique_items utility."""

def unique_items(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out


def _selftest():
    assert unique_items([1, 2, 2, 3]) == [1, 2, 3]
    assert unique_items([]) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
