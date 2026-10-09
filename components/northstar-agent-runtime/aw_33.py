"""Swap keys and values."""
def invert_dict(dd):
    return {v: k for k, v in dd.items()}
if __name__ == "__main__":
    assert invert_dict({"a": 1, "b": 2}) == {1: "a", 2: "b"}
    assert invert_dict({}) == {}
    assert invert_dict({1: "x"}) == {"x": 1}
    print("ok")
