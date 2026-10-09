"""repeat_val utility."""

def repeat_val(v, n):
    return [v] * n


def _selftest():
    assert repeat_val(0, 3) == [0, 0, 0]
    assert repeat_val("x", 0) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
