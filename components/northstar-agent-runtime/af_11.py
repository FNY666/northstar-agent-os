"""AF-module: retry_n -- Call func up to n times until it succeeds; re-raises the last error."""
from __future__ import annotations
VERSION = "af_11"
def retry_n(func, n: int = 3):
    last: Exception | None = None
    for _ in range(max(1, n)):
        try:
            return func()
        except Exception as e:
            last = e
    raise last  # type: ignore[misc]

def main() -> None:
    assert retry_n(lambda: 42) == 42
    calls = []
    def flaky():
        calls.append(1)
        if len(calls) < 3: raise RuntimeError('x')
        return 'ok'
    assert retry_n(flaky, 5) == 'ok'
    assert len(calls) == 3
    print("af_11 retry_n OK")
if __name__ == "__main__": main()
