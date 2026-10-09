"""Cosine similarity of two vectors."""
import math
def cosine_sim(a, b):
    d = dot(a, a) ** 0.5 * dot(b, b) ** 0.5
    if d == 0:
        return 0.0
    return dot(a, b) / d
def dot(a, b):
    return sum(x * y for x, y in zip(a, b))
if __name__ == "__main__":
    assert abs(cosine_sim([1, 0], [0, 1])) < 1e-9
    assert abs(cosine_sim([1, 1], [1, 1]) - 1.0) < 1e-9
    assert cosine_sim([0], [0]) == 0.0
    print("ok")
