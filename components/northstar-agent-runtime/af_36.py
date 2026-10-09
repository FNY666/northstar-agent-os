"""AF-module: once -- Wrap a callable so it runs at most once, caching its result."""
from __future__ import annotations
VERSION = "af_36"
def once(func):
    state = {'done': False, 'val': None}
    def wrap(*a, **k):
        if not state['done']:
            state['val'] = func(*a, **k)
            state['done'] = True
        return state['val']
    return wrap

def main() -> None:
    calls = []
    @once
    def f():
        calls.append(1)
        return 'r'
    assert f() == 'r'
    assert f() == 'r'
    assert len(calls) == 1
    print("af_36 once OK")
if __name__ == "__main__": main()
