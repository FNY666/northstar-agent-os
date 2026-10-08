"""Cache helpers: LRU, TTL, memoize. What this IS: in-memory caches with clear eviction. What this IS NOT: not distributed."""

from __future__ import annotations

import ast
import time
from collections import OrderedDict
from functools import wraps

#: Module version.
UTIL_18_VERSION = "util-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-18.v1"


class CacheError(Exception):
    """Cache failure."""


class LRUCache:
    """Fixed-size LRU cache."""

    def __init__(self, maxsize=128):
        if maxsize <= 0:
            raise CacheError("maxsize must be positive")
        self._maxsize = maxsize
        self._data = OrderedDict()

    def get(self, key, default=None):
        try:
            value = self._data.pop(key)
        except KeyError:
            return default
        self._data[key] = value
        return value

    def set(self, key, value):
        self._data.pop(key, None)
        self._data[key] = value
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def __len__(self):
        return len(self._data)

    def __contains__(self, key):
        return key in self._data


class TTLCache:
    """TTL cache with injectable clock (seconds)."""

    def __init__(self, ttl=60.0, clock=None):
        if ttl <= 0:
            raise CacheError("ttl must be positive")
        self._ttl = float(ttl)
        self._clock = clock or time.monotonic
        self._data = {}

    def set(self, key, value):
        self._data[key] = (value, self._clock() + self._ttl)

    def get(self, key, default=None):
        item = self._data.get(key)
        if item is None:
            return default
        value, exp = item
        if self._clock() >= exp:
            del self._data[key]
            return default
        return value


def memoize(fn):
    """Cache fn results by positional args."""
    cache = {}

    @wraps(fn)
    def wrapper(*args):
        if args not in cache:
            cache[args] = fn(*args)
        return cache[args]

    wrapper.cache_clear = cache.clear
    return wrapper


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'collections', 'functools', 'pathlib', 'time']
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    c = LRUCache(maxsize=2)
    c.set("a", 1); c.set("b", 2); c.set("c", 3)
    assert "a" not in c and c.get("b") == 2
    t = [100.0]
    tc = TTLCache(ttl=10.0, clock=lambda: t[0])
    tc.set("k", "v")
    t[0] += 11
    assert tc.get("k") is None
    calls = []
    @memoize
    def f(x):
        calls.append(x)
        return x * 2
    assert f(3) == 6 and f(3) == 6 and len(calls) == 1
    print("cache helpers OK")


if __name__ == "__main__":
    main()
