"""Elementary probability helpers (values in [0, 1]).

p_uniform, p_complement, p_union_independent, p_conditional, bayes.
"""

from __future__ import annotations


def _check_p(p: float, name: str = "p") -> None:
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"{name} must be in [0, 1]")


def p_uniform(favorable: int, total: int) -> float:
    if total <= 0:
        raise ValueError("total must be positive")
    if not 0 <= favorable <= total:
        raise ValueError("favorable must be in [0, total]")
    return favorable / total


def p_complement(p: float) -> float:
    _check_p(p)
    return 1.0 - p


def p_union_independent(pa: float, pb: float) -> float:
    """P(A or B) for independent A, B."""
    _check_p(pa, "pa")
    _check_p(pb, "pb")
    return pa + pb - pa * pb


def p_conditional(p_a_and_b: float, p_b: float) -> float:
    """P(A|B)."""
    _check_p(p_a_and_b, "p_a_and_b")
    _check_p(p_b, "p_b")
    if p_b == 0:
        raise ValueError("p_b must be non-zero")
    if p_a_and_b > p_b:
        raise ValueError("P(A and B) cannot exceed P(B)")
    return p_a_and_b / p_b


def bayes(p_b_given_a: float, p_a: float, p_b: float) -> float:
    """P(A|B) = P(B|A) * P(A) / P(B)."""
    _check_p(p_b_given_a, "p_b_given_a")
    _check_p(p_a, "p_a")
    _check_p(p_b, "p_b")
    if p_b == 0:
        raise ValueError("p_b must be non-zero")
    return p_b_given_a * p_a / p_b


def main() -> None:
    assert p_uniform(1, 6) == 1 / 6
    assert p_complement(0.3) == 0.7
    assert abs(p_union_independent(0.5, 0.5) - 0.75) < 1e-12
    assert p_conditional(0.2, 0.5) == 0.4
    # classic: 1% disease, 99% test accuracy
    post = bayes(0.99, 0.01, 0.99 * 0.01 + 0.01 * 0.99)
    assert abs(post - 0.5) < 1e-9
    print("math_12 OK")


if __name__ == "__main__":
    main()
