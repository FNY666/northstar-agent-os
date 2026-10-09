"""Cumulative sums."""
def cum_sum(xs):
    out, t = [], 0
    for x in xs:
        t += x; out.append(t)
    return out
if __name__ == "__main__":
    assert cum_sum([1,2,3]) == [1,3,6]
    assert cum_sum([]) == []
    assert cum_sum([-1,1]) == [-1,0]
    print("ok")
