"""Flatten one level of nesting."""
def flatten(nested):
    out = []
    for item in nested:
        if isinstance(item, (list, tuple)):
            out.extend(item)
        else:
            out.append(item)
    return out
if __name__ == "__main__":
    assert flatten([[1, 2], [3], 4]) == [1, 2, 3, 4]
    assert flatten([]) == []
    assert flatten([(1, 2)]) == [1, 2]
    print("ok")
