"""FizzBuzz Label, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_42.v1"
def fizzbuzz(n: int) -> str:
    if n <= 0: raise ValueError("n>0")
    return "FizzBuzz" if n % 15 == 0 else "Fizz" if n % 3 == 0 else "Buzz" if n % 5 == 0 else str(n)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert fizzbuzz(15) == "FizzBuzz"
    assert fizzbuzz(3) == "Fizz"
    assert fizzbuzz(7) == "7"
    assert stdlib_only()
    print("ag_42 OK")
if __name__ == "__main__": main()
