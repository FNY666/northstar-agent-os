"""ax_49: drop_while utility (stdlib only)."""
def drop_while(pred, items):
    out = list(items)
    i = 0
    while i < len(out) and pred(out[i]): i += 1
    return out[i:]


def run_tests():
    assert (drop_while(lambda x: x < 3, [1,2,5,1])) == [5, 1], 'drop_while(lambda x: x < 3, [1,2,5,1])'
    assert (drop_while(lambda x: False, [1])) == [1], 'drop_while(lambda x: False, [1])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_49: ok")
