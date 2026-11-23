# Task fixture

`summarize(text)` returns `{"count": int, "total": number}` from CSV columns `name,amount`. Empty/header-only input and blank records produce no records. Quoted commas and embedded newlines are valid CSV.

Run public checks with `python3 -m unittest discover -s tests -v`.
