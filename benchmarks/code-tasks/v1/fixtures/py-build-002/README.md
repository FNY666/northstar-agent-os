# Countdown test fixture

Production `Countdown(ttl, clock=None)` already exposes a deterministic clock.
Repair the tests to cover before, exactly at, and after expiry without sleeping
or changing production behavior. Retain at least three meaningful assertions.
