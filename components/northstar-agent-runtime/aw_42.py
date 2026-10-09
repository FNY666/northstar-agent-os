"""Leading items while pred holds."""
def take_while(xs, pred):
    out = []
    for x in xs:
        if not pred(x):
            break
        out.append(x)
    return out
if __name__ == "__main__":
    assert take_while([1,2,3,1], lambda x: x < 3) == [1,2]
    assert take_while([], bool) == []
    assert take_while([1,1], lambda x: x) == [1,1]
    print("ok")
