"""Utility ay_43: cosine_sim."""


def cosine_sim(a, b):
    """Return cosine_sim result."""
    den = (sum(x * x for x in a) ** 0.5) * (sum(x * x for x in b) ** 0.5)
    return sum(x * y for x, y in zip(a, b)) / den if den else 0.0


def _run_tests():
    assert abs(cosine_sim([1, 0], [0, 1])) < 1e-9
    assert abs(cosine_sim([1, 1], [1, 1]) - 1.0) < 1e-9


if __name__ == '__main__':
    _run_tests()
    print('OK')
