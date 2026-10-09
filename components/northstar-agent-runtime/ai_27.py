"""Gradient Step Util (AI-U-027), Simulated."""
from __future__ import annotations
VERSION = "ai_27.v1"

def grad_step(weights, grads, lr):
    return [w - lr * g for w, g in zip(weights, grads)]

def main() -> None:
    assert grad_step([1.0, 2.0], [0.1, 0.2], 0.5) == [0.95, 1.9]
    assert grad_step([], [], 0.1) == []
    print(f"ai_27 OK")
if __name__ == "__main__": main()
