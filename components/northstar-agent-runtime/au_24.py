"""au_24: Digital root."""
def digital_root(n):
    """Repeated digit sum until single digit."""
    n = abs(n)
    while n >= 10:
        n = sum(int(d) for d in str(n))
    return n

def _run_tests():
    assert digital_root(38) == 2
    assert digital_root(9) == 9

if __name__ == "__main__":
    _run_tests()
    print("au_24 OK")
