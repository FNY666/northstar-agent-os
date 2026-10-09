"""z_27: base64enc."""
from __future__ import annotations
VERSION = "z_27.v1"
def base64enc(s):
    import base64
    return base64.b64encode(s.encode()).decode()
def base64dec(t):
    import base64
    return base64.b64decode(t.encode()).decode()

def main() -> None:
    assert base64dec(base64enc('hi'))=='hi'
    assert base64enc('ab')=='YWI='
    print('z_27 base64enc OK')

if __name__ == "__main__": main()
