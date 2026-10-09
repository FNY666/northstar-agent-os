"""z_12: is_prime."""
from __future__ import annotations
VERSION = "z_12.v1"
def is_prime(n):
    if n<2: return False
    i=2
    while i*i<=n:
        if n%i==0: return False
        i+=1
    return True

def main() -> None:
    assert is_prime(17)
    assert not is_prime(15)
    print('z_12 is_prime OK')

if __name__ == "__main__": main()
