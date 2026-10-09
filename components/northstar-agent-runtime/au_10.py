"""au_10: Flatten one level of nesting."""
def flatten(xs):
    """Flatten one level of nested lists."""
    out = []
    for x in xs:
        out.extend(x if isinstance(x, list) else [x])
    return out

def _run_tests():
    assert flatten([[1, 2], [3]]) == [1, 2, 3]
    assert flatten([1, 2]) == [1, 2]

if __name__ == "__main__":
    _run_tests()
    print("au_10 OK")
