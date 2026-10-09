"""AJ-50: ISO8601 parse."""
from __future__ import annotations
VERSION = "aj_50.v1"


import datetime
def parse_iso(s):
    return datetime.datetime.fromisoformat(s)

def main() -> None:
    assert parse_iso('2026-01-02T03:04:05').year == 2026
    assert parse_iso('2026-01-02').month == 1
    print(f"aj_50 OK")
if __name__ == "__main__": main()
