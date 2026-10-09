"""AF-module: csv_to_dicts -- Parse a CSV string into a list of row dicts."""
from __future__ import annotations
VERSION = "af_40"
import csv, io
def csv_to_dicts(text: str) -> list:
    return list(csv.DictReader(io.StringIO(text)))

def main() -> None:
    rows = csv_to_dicts('a,b\n1,2\n3,4\n')
    assert rows == [{'a': '1', 'b': '2'}, {'a': '3', 'b': '4'}]
    assert csv_to_dicts('a\n') == []
    assert csv_to_dicts('') == []
    print("af_40 csv_to_dicts OK")
if __name__ == "__main__": main()
