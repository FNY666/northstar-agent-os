"""Reverse decimal digits of n."""
def reverse_int(n):
    s = str(abs(n))[::-1]
    return (-1 if n < 0 else 1) * int(s)
if __name__ == "__main__":
    assert reverse_int(123) == 321
    assert reverse_int(-456) == -654
    assert reverse_int(100) == 1
    print("ok")
