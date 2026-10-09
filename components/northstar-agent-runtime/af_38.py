"""AF-module: guarded -- Call func; return default instead of raising."""
from __future__ import annotations
VERSION = "af_38"
def guarded(func, default=None, *a, **k):
    try:
        return func(*a, **k)
    except Exception:
        return default

def main() -> None:
    assert guarded(int, 0, '12') == 12
    assert guarded(int, 0, 'nope') == 0
    assert guarded(lambda: 1 / 0, 'd') == 'd'
    print("af_38 guarded OK")
if __name__ == "__main__": main()
