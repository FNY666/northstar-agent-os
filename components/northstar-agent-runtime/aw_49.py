"""One bubble-sort pass."""
def bubble_pass(xs):
    xs = list(xs)
    for i in range(len(xs) - 1):
        if xs[i] > xs[i+1]:
            xs[i], xs[i+1] = xs[i+1], xs[i]
    return xs
if __name__ == "__main__":
    assert bubble_pass([3,2,1]) == [2,1,3]
    assert bubble_pass([1,2]) == [1,2]
    assert bubble_pass([]) == []
    print("ok")
