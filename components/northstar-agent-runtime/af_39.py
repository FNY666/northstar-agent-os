"""AF-module: json_pretty -- JSON string with indent=2 and sorted keys."""
from __future__ import annotations
VERSION = "af_39"
import json
def json_pretty(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)

def main() -> None:
    assert json_pretty({'b': 1, 'a': 2}) == '{\n  "a": 2,\n  "b": 1\n}'
    assert json_pretty([]) == '[]'
    assert json_pretty({'x': [1]}) .startswith('{')
    print("af_39 json_pretty OK")
if __name__ == "__main__": main()
