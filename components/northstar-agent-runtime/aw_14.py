"""n! for n >= 0."""
def factorial_n(n):
    r = 1
    for i in range(2, n+1):
        r *= i
    return r
if __name__ == "__main__":
    assert factorial_n(0) == 1
    assert factorial_n(5) == 120
    assert factorial_n(10) == 3628800
    print("ok")
