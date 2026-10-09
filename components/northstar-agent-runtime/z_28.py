"""z_28: hexify."""
from __future__ import annotations
VERSION = "z_28.v1"
def hexify(b):
    return b.hex() if isinstance(b,bytes) else bytes(b,'utf8').hex()

def main() -> None:
    assert hexify('ab')=='6162'
    assert hexify(b'\xff')=='ff'
    print('z_28 hexify OK')

if __name__ == "__main__": main()
