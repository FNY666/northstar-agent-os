"""CAPTCHA integration interface (input defense), Simulated

What this IS: Defines the CAPTCHA challenge/verify contract with a mock implementation for tests. Real providers plug in behind the interface.

What this IS NOT:
* The mock is NOT a real CAPTCHA -- it exists for wiring and tests only.
* Never treat mock verification as bot protection in production.
"""

from __future__ import annotations

import secrets

#: Module version.
MODULE_VERSION = "input-defense-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-25.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'ast', 'secrets', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


class CaptchaChallenge:
    """Issued challenge."""

    def __init__(self, challenge_id, prompt):
        self.challenge_id = challenge_id
        self.prompt = prompt


class MockCaptchaProvider:
    """Mock CAPTCHA provider for wiring/tests. NOT real protection."""

    def __init__(self):
        self._answers = {}

    def issue(self):
        """Issue a challenge; answer is embedded for the mock only."""
        cid = __import__("secrets").token_hex(8)
        answer = __import__("secrets").token_hex(4)
        self._answers[cid] = answer
        return CaptchaChallenge(cid, "mock: echo " + answer), answer

    def verify(self, challenge_id, response):
        """Verify a response. Returns True only on exact match."""
        if not challenge_id or not isinstance(response, str):
            return False
        expected = self._answers.pop(challenge_id, None)
        if expected is None:
            return False  # unknown or already used (replay rejected)
        return response == expected


def require_captcha(provider, challenge_id, response):
    """Gate helper. Raises InputDefenseError when verification fails."""
    if not provider.verify(challenge_id, response):
        raise InputDefenseError("captcha verification failed")
    return True



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    p = MockCaptchaProvider()
    ch, answer = p.issue()
    assert p.verify(ch.challenge_id, answer) is True
    # Replay rejected.
    assert p.verify(ch.challenge_id, answer) is False
    ch2, ans2 = p.issue()
    assert p.verify(ch2.challenge_id, "wrong") is False
    try:
        require_captcha(p, ch2.challenge_id, "wrong")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-25.v1 OK")


if __name__ == "__main__":
    main()
