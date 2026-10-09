"""AF-module: snake_to_camel -- Convert snake_case to lowerCamelCase."""
from __future__ import annotations
VERSION = "af_08"
def snake_to_camel(s: str) -> str:
    parts = s.split('_')
    return parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])

def main() -> None:
    assert snake_to_camel('hello_world') == 'helloWorld'
    assert snake_to_camel('a_b_c') == 'aBC'
    assert snake_to_camel('plain') == 'plain'
    print("af_08 snake_to_camel OK")
if __name__ == "__main__": main()
