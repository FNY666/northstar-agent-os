"""au_34: Clamp value to range."""
def clamp(v, lo, hi):
    """Clamp v into [lo, hi]."""
    return max(lo, min(hi, v))

def _run_tests():
    assert clamp(10, 0, 5) == 5
    assert clamp(-1, 0, 5) == 0

if __name__ == "__main__":
    _run_tests()
    print("au_34 OK")
