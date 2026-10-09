"""z_29: url_join."""
from __future__ import annotations
VERSION = "z_29.v1"
def url_join(base,path):
    return base.rstrip('/')+'/'+path.lstrip('/')

def main() -> None:
    assert url_join('http://x/','a/b')=='http://x/a/b'
    assert url_join('http://x','a')=='http://x/a'
    print('z_29 url_join OK')

if __name__ == "__main__": main()
