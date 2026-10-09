"""invert_dict utility."""

def invert_dict(d):
    return {v: k for k, v in d.items()}


def _selftest():
    assert invert_dict({"a": 1}) == {1: "a"}
    assert invert_dict({}) == {}


if __name__ == "__main__":
    _selftest()
    print("ok")
