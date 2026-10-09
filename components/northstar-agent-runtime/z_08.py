"""z_08: snake_to_camel."""
from __future__ import annotations
VERSION = "z_08.v1"
def snake_to_camel(s):
    parts=s.split('_'); return parts[0]+''.join(p.title() for p in parts[1:])

def main() -> None:
    assert snake_to_camel('foo_bar_baz')=='fooBarBaz'
    assert snake_to_camel('x')=='x'
    print('z_08 snake_to_camel OK')

if __name__ == "__main__": main()
