# Task fixture

`Cache(clock=None)` stores values with `set(key, value, ttl)` and reads them with `get(key)`. Missing or expired entries raise `KeyError`. Expiry is exclusive: an entry is live only while `clock() < expires`.

Run public checks with `python3 -m unittest discover -s tests -v`.
