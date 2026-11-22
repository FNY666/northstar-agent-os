# Task fixture

Preserve `stamp(message)` and its exact `message,created_at` result shape. Add optional keyword-only `clock` injection; `None` uses the current `time.time`. A supplied clock is invoked once without a global monkeypatch.

Run public checks with `python3 -m unittest discover -s tests -v`.
