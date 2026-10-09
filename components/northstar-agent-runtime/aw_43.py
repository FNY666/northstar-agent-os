"""Drop leading items while pred holds."""
def drop_while(xs, pred):
    i = 0
    while i < len(xs) and pred(xs[i]):
        i += 1
    return xs[i:]
if __name__ == "__main__":
    assert drop_while([1,2,3,1], lambda x: x < 3) == [3,1]
    assert drop_while([], bool) == []
    assert drop_while([1,1], lambda x: x) == []
    print("ok")
