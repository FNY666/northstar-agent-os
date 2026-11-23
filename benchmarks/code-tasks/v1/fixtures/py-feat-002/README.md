# Task fixture

`merge_config(defaults, file_values=None, env=None, overrides=None)` merges supplied dictionaries in that order. Keys must exist in `defaults`. Explicit falsy values remain values; the returned structure must not alias or mutate inputs.

Run public checks with `python3 -m unittest discover -s tests -v`.
