# Task fixture

`parse(fmt, text)` supports exact format names `json,csv` and keeps existing outputs/errors. Add `register_parser(fmt, callable)` without permitting duplicate registrations. Parser exceptions must propagate unchanged.

Run public checks with `python3 -m unittest discover -s tests -v`.
