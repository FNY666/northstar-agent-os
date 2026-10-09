"""merge_dicts utility."""

def merge_dicts(a, b):
    return {**a, **b}


def _selftest():
    assert merge_dicts({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}
    assert merge_dicts({}, {}) == {}


if __name__ == "__main__":
    _selftest()
    print("ok")
