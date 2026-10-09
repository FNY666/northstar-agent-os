"""Take items from seq while predicate holds (list)."""
def take_while(pred, seq):
    out = []
    for x in seq:
        if not pred(x):
            break
        out.append(x)
    return out
if __name__ == "__main__":
    assert take_while(lambda x: x < 3, [1, 2, 3, 1]) == [1, 2]
    assert take_while(lambda x: True, [1, 2]) == [1, 2]
    assert take_while(lambda x: False, [1]) == []
    print("ok")
