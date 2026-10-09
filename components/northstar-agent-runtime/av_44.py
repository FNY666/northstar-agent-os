"""Factorial of a non-negative int."""
def factorial(n):
    if n < 0:
        raise ValueError("negative")
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r
if __name__ == "__main__":
    assert factorial(0) == 1
    assert factorial(5) == 120
    assert factorial(3) == 6
    print("ok")
