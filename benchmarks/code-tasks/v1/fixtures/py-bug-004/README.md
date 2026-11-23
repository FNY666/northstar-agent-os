# Task fixture

`collect(fetch)` starts with cursor `None`, appends each page's complete `items`, and terminates on an empty page or `next_cursor=None`. Reusing a cursor raises `ValueError`; duplicate item values are legitimate.

Run public checks with `python3 -m unittest discover -s tests -v`.
