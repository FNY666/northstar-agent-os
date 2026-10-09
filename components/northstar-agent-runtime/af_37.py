"""AF-module: pipe -- Compose functions left-to-right: pipe(f, g)(x) == g(f(x))."""
from __future__ import annotations
VERSION = "af_37"
def pipe(*funcs):
    def run(x):
        for f in funcs:
            x = f(x)
        return x
    return run

def main() -> None:
    f = pipe(lambda x: x + 1, lambda x: x * 10)
    assert f(2) == 30
    assert pipe()(5) == 5
    assert pipe(str)(7) == '7'
    print("af_37 pipe OK")
if __name__ == "__main__": main()
