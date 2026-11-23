# Task fixture

`summarize(lines)` returns `records,total` for JSON objects with a numeric `value`. Process each physical line before requesting the next, skip blanks, and include the physical line number in validation errors. Booleans are not numeric values.

Run public checks with `python3 -m unittest discover -s tests -v`.
