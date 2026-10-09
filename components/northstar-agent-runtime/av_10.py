"""Sum of decimal digits of an int."""
def digit_sum(n):
    return sum(int(d) for d in str(abs(n)))
if __name__ == "__main__":
    assert digit_sum(12345) == 15
    assert digit_sum(-909) == 18
    assert digit_sum(0) == 0
    print("ok")
