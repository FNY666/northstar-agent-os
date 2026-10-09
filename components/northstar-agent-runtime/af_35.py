"""AF-module: memoize -- Cache a function's results keyed by its arguments."""
from __future__ import annotations
VERSION = "af_35"
import functools
def memoize(func):
    @functools.wraps(func)
    def wrap(*a, **k):
        key = (a, tuple(sorted(k.items())))
        if key not in wrap._cache:
            wrap._cache[key] = func(*a, **k)
        return wrap._cache[key]
    wrap._cache = {}
    return wrap

def main() -> None:
    calls = []
    @memoize
    def f(x):
        calls.append(x)
        return x * 2
    assert f(3) == 6
    assert f(3) == 6
    assert calls == [3]
    assert f(4) == 8
    print("af_35 memoize OK")
if __name__ == "__main__": main()
