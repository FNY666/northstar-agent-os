"""A monotonic countdown with an injectable clock."""
import time

class Countdown:
    def __init__(self, ttl, *, clock=None):
        if ttl < 0:
            raise ValueError("ttl must be non-negative")
        self.clock = time.monotonic if clock is None else clock
        self.deadline = self.clock() + ttl

    def expired(self):
        return self.clock() >= self.deadline
