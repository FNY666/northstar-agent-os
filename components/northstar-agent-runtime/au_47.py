"""au_47: XOR of list."""
import functools, operator
def xor_all(xs):
    """XOR all integers together."""
    return functools.reduce(operator.xor, xs, 0)

def _run_tests():
    assert xor_all([1, 2, 3]) == 0
    assert xor_all([5]) == 5

if __name__ == "__main__":
    _run_tests()
    print("au_47 OK")
