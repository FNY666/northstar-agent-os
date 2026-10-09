"""Flatten one level of nesting."""
def flatten_one(xss):
    return [x for xs in xss for x in xs]
if __name__ == "__main__":
    assert flatten_one([[1,2],[3],[4,5]]) == [1,2,3,4,5]
    assert flatten_one([]) == []
    assert flatten_one([[]]) == []
    print("ok")
