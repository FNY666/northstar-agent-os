"""AF-module: truncate -- Truncate to max_len chars, ending with '...' when cut."""
from __future__ import annotations
VERSION = "af_47"
def truncate(s: str, max_len: int) -> str:
    if max_len < 0:
        raise ValueError('max_len must be >= 0')
    return s if len(s) <= max_len else s[:max(0, max_len - 3)] + '...'

def main() -> None:
    assert truncate('hello world', 8) == 'hello...'
    assert truncate('hi', 8) == 'hi'
    assert truncate('abcdef', 6) == 'abcdef'
    print("af_47 truncate OK")
if __name__ == "__main__": main()
