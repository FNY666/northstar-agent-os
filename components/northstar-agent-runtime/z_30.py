"""z_30: query_parse."""
from __future__ import annotations
VERSION = "z_30.v1"
def query_parse(qs):
    from urllib.parse import parse_qsl
    return dict(parse_qsl(qs))

def main() -> None:
    assert query_parse('a=1&b=2')=={'a':'1','b':'2'}
    assert query_parse('')=={}
    print('z_30 query_parse OK')

if __name__ == "__main__": main()
