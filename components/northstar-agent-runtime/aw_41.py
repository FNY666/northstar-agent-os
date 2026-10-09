"""Insert sep between items."""
def intersperse(xs, sep):
    out = []
    for i, x in enumerate(xs):
        if i:
            out.append(sep)
        out.append(x)
    return out
if __name__ == "__main__":
    assert intersperse([1,2,3], 0) == [1,0,2,0,3]
    assert intersperse([1], 0) == [1]
    assert intersperse([], 0) == []
    print("ok")
