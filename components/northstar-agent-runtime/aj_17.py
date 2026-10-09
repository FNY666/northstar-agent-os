"""AJ-17: Is prime."""
from __future__ import annotations
VERSION = "aj_17.v1"


def is_prime(n):
    if n < 2: return False
    return all(n % i for i in range(2, int(n**0.5)+1))

def main() -> None:
    assert is_prime(13) and not is_prime(15)
    assert not is_prime(1)
    print(f"aj_17 OK")
if __name__ == "__main__": main()
