"""AJ-25: Camel to snake."""
from __future__ import annotations
VERSION = "aj_25.v1"


import re
def camel_to_snake(s):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()

def main() -> None:
    assert camel_to_snake('helloWorldX') == 'hello_world_x'
    assert camel_to_snake('ABC') == 'a_b_c'
    print(f"aj_25 OK")
if __name__ == "__main__": main()
