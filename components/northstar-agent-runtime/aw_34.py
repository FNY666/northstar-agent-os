"""Merge dicts; later wins."""
def merge_dicts(*dds):
    out = {}
    for dd in dds:
        out.update(dd)
    return out
if __name__ == "__main__":
    assert merge_dicts({"a":1},{"a":2,"b":3}) == {"a":2,"b":3}
    assert merge_dicts() == {}
    assert merge_dicts({"x":0}) == {"x":0}
    print("ok")
