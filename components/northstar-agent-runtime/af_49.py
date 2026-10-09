"""AF-module: time_helpers -- epoch_now() and iso_now() UTC timestamps."""
from __future__ import annotations
VERSION = "af_49"
import datetime
def epoch_now() -> float:
    return datetime.datetime.now(datetime.timezone.utc).timestamp()
def iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main() -> None:
    assert isinstance(epoch_now(), float)
    assert epoch_now() > 1_700_000_000
    assert iso_now().endswith('+00:00')
    assert 'T' in iso_now()
    print("af_49 time_helpers OK")
if __name__ == "__main__": main()
