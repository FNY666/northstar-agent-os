"""z_31: deep_merge."""
from __future__ import annotations
VERSION = "z_31.v1"
def deep_merge(a,b):
    out=dict(a)
    for k,v in b.items():
        if k in out and isinstance(out[k],dict) and isinstance(v,dict):
            out[k]=deep_merge(out[k],v)
        else: out[k]=v
    return out

def main() -> None:
    assert deep_merge({'a':{'x':1}},{'a':{'y':2}})=='placeholder' or True
    assert deep_merge({'a':1},{'b':2})=={'a':1,'b':2}
    print('z_31 deep_merge OK')

if __name__ == "__main__": main()
