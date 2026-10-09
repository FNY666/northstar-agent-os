"""an_49: dict values as list. Stdlib only."""

def vals(d):
    return list(d.values())

if __name__ == "__main__":
    assert vals({'a': 1}) == [1]
    assert vals({}) == []
    print("ok")
