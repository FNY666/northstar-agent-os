"""Reverse the digits of an int, preserving sign."""
def reverse_int(n):
    sign = -1 if n < 0 else 1
    return sign * int(str(abs(n))[::-1])
if __name__ == "__main__":
    assert reverse_int(123) == 321
    assert reverse_int(-120) == -21
    assert reverse_int(7) == 7
    print("ok")
