"""Sum of decimal digits of n."""
def digit_sum(n):
    return sum(int(ch) for ch in str(abs(n)))
if __name__ == "__main__":
    assert digit_sum(123) == 6
    assert digit_sum(-99) == 18
    assert digit_sum(0) == 0
    print("ok")
