"""AJ-24: Snake to camel."""
from __future__ import annotations
VERSION = "aj_24.v1"


def snake_to_camel(s):
    p = s.split('_')
    return p[0] + ''.join(w.capitalize() for w in p[1:])

def main() -> None:
    assert snake_to_camel('hello_world_x') == 'helloWorldX'
    assert snake_to_camel('abc') == 'abc'
    print(f"aj_24 OK")
if __name__ == "__main__": main()
