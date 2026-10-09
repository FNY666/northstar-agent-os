"""z_35: invert_dict."""
from __future__ import annotations
VERSION = "z_35.v1"
def invert_dict(d):
    return {v:k for k,v in d.items()}

def main() -> None:
    assert invert_dict({'a':1,'b':2})=={1:'a',2:'b'}
    assert invert_dict({})=={}
    print('z_35 invert_dict OK')

if __name__ == "__main__": main()
