"""Index of minimum element."""
def arg_min(xs):
    return min(range(len(xs)), key=xs.__getitem__)
if __name__ == "__main__":
    assert arg_min([3,1,2]) == 1
    assert arg_min([5]) == 0
    assert arg_min([-1,-2,-3]) == 2
    print("ok")
