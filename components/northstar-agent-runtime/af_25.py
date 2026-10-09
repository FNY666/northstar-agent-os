"""AF-module: flatten_dict -- Nested dict to dotted-key flat dict."""
from __future__ import annotations
VERSION = "af_25"
def flatten_dict(d: dict, prefix: str = '') -> dict:
    out: dict = {}
    for k, v in d.items():
        key = f'{prefix}.{k}' if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten_dict(v, key))
        else:
            out[key] = v
    return out

def main() -> None:
    assert flatten_dict({'a': {'b': 1}, 'c': 2}) == {'a.b': 1, 'c': 2}
    assert flatten_dict({}) == {}
    assert flatten_dict({'a': {}}) == {}
    print("af_25 flatten_dict OK")
if __name__ == "__main__": main()
