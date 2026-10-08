"""Expression tree: build from postfix, evaluate, infix print. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Union

@dataclass
class ENode:
    val: Union[str, float]
    left: Optional["ENode"] = None
    right: Optional["ENode"] = None

OPS = {"+", "-", "*", "/"}

def build_postfix(tokens) -> ENode:
    stack = []
    for tok in tokens:
        if tok in OPS:
            r = stack.pop(); l = stack.pop()
            stack.append(ENode(tok, l, r))
        else:
            stack.append(ENode(float(tok)))
    assert len(stack) == 1
    return stack[0]

def evaluate(n: ENode) -> float:
    if n.val not in OPS: return float(n.val)
    l, r = evaluate(n.left), evaluate(n.right)
    return {"+": l + r, "-": l - r, "*": l * r, "/": l / r}[n.val]

def to_infix(n: ENode) -> str:
    if n.val not in OPS:
        v = float(n.val); return str(int(v) if v.is_integer() else v)
    return f"({to_infix(n.left)} {n.val} {to_infix(n.right)})"

def main() -> None:
    t = build_postfix(["3", "4", "+", "2", "*"])
    assert evaluate(t) == 14.0
    assert to_infix(t) == "((3 + 4) * 2)"
    t2 = build_postfix(["10", "2", "/"])
    assert evaluate(t2) == 5.0
    print("tree_37 Expression tree OK")

if __name__ == "__main__":
    main()
