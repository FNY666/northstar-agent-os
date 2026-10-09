"""flatten_dict utility."""

def flatten_dict(d, p='', s='.'):  # noqa
    o = {}
    for k, v in d.items():
        nk = f'{p}{s}{k}' if p else str(k)
        o.update(flatten_dict(v, nk, s) if isinstance(v, dict) else {nk: v})
    return o


def _selftest():
    assert flatten_dict({"a": {"b": 1}}) == {"a.b": 1}
    assert flatten_dict({}) == {}


if __name__ == "__main__":
    _selftest()
    print("ok")
