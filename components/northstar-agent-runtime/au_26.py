"""au_26: Count set bits."""
def count_bits(n):
    """Count 1-bits in the binary representation of |n|."""
    return bin(abs(n)).count('1')

def _run_tests():
    assert count_bits(7) == 3
    assert count_bits(0) == 0

if __name__ == "__main__":
    _run_tests()
    print("au_26 OK")
