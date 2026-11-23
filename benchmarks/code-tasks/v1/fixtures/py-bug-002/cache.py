"""A TTL cache; clock values are monotonic seconds."""
import time

class Cache:
    def __init__(self, clock=None):
        self.clock = clock or time.monotonic
        self.entries = {}

    def set(self, key, value, ttl):
        if ttl < 0:
            raise ValueError("ttl must be non-negative")
        self.entries[key] = (value, self.clock() + ttl)

    def get(self, key):
        value, expires = self.entries[key]
        if self.clock() > expires:
            del self.entries[key]
            raise KeyError(key)
        return value
