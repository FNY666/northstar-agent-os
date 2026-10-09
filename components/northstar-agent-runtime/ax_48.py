"""ax_48: take_while utility (stdlib only)."""
def take_while(pred, items):
    out = []
    for x in items:
        if not pred(x): break
        out.append(x)
    return out


def run_tests():
    assert (take_while(lambda x: x < 3, [1,2,5,1])) == [1, 2], 'take_while(lambda x: x < 3, [1,2,5,1])'
    assert (take_while(lambda x: True, [])) == [], 'take_while(lambda x: True, [])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_48: ok")
