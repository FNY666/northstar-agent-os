"""am_44: flatten_once utility (stdlib only)."""

def flatten_once(items):
    out = []
    for sub in items:
        out.extend(sub)
    return out

def _run_tests():
    assert flatten_once([[1, 2], [3]]) == [1, 2, 3], 'am_44'
    assert flatten_once([]) == [], 'am_44'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_44: all tests passed")
