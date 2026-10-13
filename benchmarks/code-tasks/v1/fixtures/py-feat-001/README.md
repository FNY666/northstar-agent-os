# Task fixture

`normalize_names(names, limit=100)` accepts an iterable of text, collapses Unicode whitespace, and case-folds each name. Preserve order, duplicate values, and empty names. Reject invalid limits, oversized batches, and non-text names.

Run public checks with `python3 -m unittest discover -s tests -v`.
