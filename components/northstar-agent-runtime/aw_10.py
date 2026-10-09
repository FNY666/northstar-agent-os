"""Index of maximum element."""
def arg_max(xs):
    return max(range(len(xs)), key=xs.__getitem__)
if __name__ == "__main__":
    assert arg_max([3,1,2]) == 0
    assert arg_max([5]) == 0
    assert arg_max([-1,-2,-3]) == 0
    print("ok")
