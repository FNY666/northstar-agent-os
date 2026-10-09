"""drop_while utility."""

def drop_while(pred, items):
    items = list(items)
    i = 0
    while i < len(items) and pred(items[i]):
        i += 1
    return items[i:]


def _self_test():
    assert drop_while(lambda x: x < 3, [1,2,4,1]) == [4,1]
    assert drop_while(lambda x: True, [1]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_26: OK")
