"""an_30: check suffix. Stdlib only."""

def ends(s, p):
    return s.endswith(p)

if __name__ == "__main__":
    assert ends('hello', 'lo')
    assert not ends('hello', 'he')
    print("ok")
