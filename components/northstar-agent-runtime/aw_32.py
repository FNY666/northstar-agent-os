"""Flatten nested dict with dot keys."""
def flatten_dict(dd, pre=""):
    out = {}
    for k, v in dd.items():
        kk = f"{pre}.{k}" if pre else str(k)
        if isinstance(v, dict):
            out.update(flatten_dict(v, kk))
        else:
            out[kk] = v
    return out
if __name__ == "__main__":
    assert flatten_dict({"a": {"b": 1}}) == {"a.b": 1}
    assert flatten_dict({}) == {}
    assert flatten_dict({"x": 1, "y": {"z": 2}}) == {"x": 1, "y.z": 2}
    print("ok")
