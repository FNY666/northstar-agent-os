"""chunk_dict utility."""

def chunk_dict(d, n):
    items = list(d.items())
    return [dict(items[i:i+n]) for i in range(0, len(items), n)]


def _self_test():
    assert chunk_dict({'a':1,'b':2,'c':3}, 2) == [{'a':1,'b':2},{'c':3}]
    assert chunk_dict({}, 2) == []


if __name__ == "__main__":
    _self_test()
    print("ap_48: OK")
