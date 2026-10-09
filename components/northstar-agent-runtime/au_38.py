"""au_38: Hamming distance."""
def hamming_dist(a, b):
    """Count positions where equal-length sequences differ."""
    if len(a) != len(b):
        raise ValueError('length mismatch')
    return sum(1 for x, y in zip(a, b) if x != y)

def _run_tests():
    assert hamming_dist('abc', 'abd') == 1
    assert hamming_dist([1, 1], [1, 1]) == 0

if __name__ == "__main__":
    _run_tests()
    print("au_38 OK")
