"""z_14: fib."""
from __future__ import annotations
VERSION = "z_14.v1"
def fib(n):
    a,b=0,1
    for _ in range(n): a,b=b,a+b
    return a

def main() -> None:
    assert fib(10)==55
    assert fib(0)==0
    print('z_14 fib OK')

if __name__ == "__main__": main()
