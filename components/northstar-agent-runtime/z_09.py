"""z_09: camel_to_snake."""
from __future__ import annotations
VERSION = "z_09.v1"
def camel_to_snake(s):
    import re
    return re.sub(r'(?<!^)(?=[A-Z])','_',s).lower()

def main() -> None:
    assert camel_to_snake('fooBarBaz')=='foo_bar_baz'
    assert camel_to_snake('x')=='x'
    print('z_09 camel_to_snake OK')

if __name__ == "__main__": main()
