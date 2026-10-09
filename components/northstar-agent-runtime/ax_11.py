"""ax_11: dedup utility (stdlib only)."""
def dedup(items):
    seen, out = set(), []
    for x in items:
        if x not in seen: seen.add(x); out.append(x)
    return out


def run_tests():
    assert (dedup([1,2,2,3,1])) == [1, 2, 3], 'dedup([1,2,2,3,1])'
    assert (dedup([])) == [], 'dedup([])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_11: ok")
