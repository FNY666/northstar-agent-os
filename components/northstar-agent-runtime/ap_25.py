"""take_while utility."""

def take_while(pred, items):
    out = []
    for x in items:
        if not pred(x): break
        out.append(x)
    return out


def _self_test():
    assert take_while(lambda x: x < 3, [1,2,4,1]) == [1,2]
    assert take_while(lambda x: True, []) == []


if __name__ == "__main__":
    _self_test()
    print("ap_25: OK")
