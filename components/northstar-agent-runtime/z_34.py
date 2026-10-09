"""z_34: flat_dict."""
from __future__ import annotations
VERSION = "z_34.v1"
def flat_dict(d,sep='.'):
    out={}
    def rec(o,pre):
        for k,v in o.items():
            key=f'{pre}{sep}{k}' if pre else k
            rec(v,key) if isinstance(v,dict) else out.__setitem__(key,v)
    rec(d,''); return out

def main() -> None:
    assert flat_dict({'a':{'b':1},'c':2})=={'a.b':1,'c':2}
    assert flat_dict({})=={}
    print('z_34 flat_dict OK')

if __name__ == "__main__": main()
