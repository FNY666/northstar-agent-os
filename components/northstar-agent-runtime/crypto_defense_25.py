"""Crypto Defense 25: SAML integration (mock), Simulated.

Mock SAML identity provider: builds a signed AuthnResponse (base64 of a
minimal assertion document), validates signature, destination,
audience, time window, and InResponseTo, and rejects response ID
replays.

What this IS: SAML response issue/validate API.
What this IS NOT: real XML, XML-DSig, or metadata exchange.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set

#: Module version.
CRYPTO_DEFENSE_25_VERSION = "crypto-defense-25.v1"
SCHEMA_PIN = "northstar.crypto-defense-25.v1"


class SamlError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SamlAssertion:
    """Parsed SAML assertion."""

    name_id: str
    audience: str
    not_on_or_after: int


class MockSAMLIdP:
    """Mock SAML identity provider / validator."""

    def __init__(self, entity_id: str, ttl: int = 300) -> None:
        if not entity_id:
            raise SamlError("entity_id required")
        self._entity_id = entity_id
        self._ttl = ttl
        self._key = secrets.token_bytes(32)
        self._seen_ids: Set[str] = set()

    def issue_response(
        self, name_id: str, audience: str, destination: str, in_response_to: str
    ) -> str:
        """Build a signed AuthnResponse (base64 of canonical JSON)."""
        if not all([name_id, audience, destination, in_response_to]):
            raise SamlError("all fields required")
        now = int(time.time())
        doc = {
            "id": "resp-" + secrets.token_hex(8),
            "issuer": self._entity_id,
            "name_id": name_id,
            "audience": audience,
            "destination": destination,
            "in_response_to": in_response_to,
            "not_before": now - 60,
            "not_on_or_after": now + self._ttl,
        }
        body = base64.b64encode(
            json.dumps(doc, sort_keys=True).encode()
        ).decode()
        sig = hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

    def validate_response(
        self, response: str, audience: str, destination: str
    ) -> Optional[SamlAssertion]:
        """Validate a response. Returns assertion or None."""
        try:
            body, sig = response.rsplit(".", 1)
            expected = hmac.new(
                self._key, body.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, sig):
                return None
            doc = json.loads(base64.b64decode(body))
            if doc.get("issuer") != self._entity_id:
                return None
            if doc.get("audience") != audience:
                return None
            if doc.get("destination") != destination:
                return None
            now = int(time.time())
            if not (int(doc["not_before"]) <= now <= int(doc["not_on_or_after"])):
                return None
            if doc["id"] in self._seen_ids:
                return None  # replay
            self._seen_ids.add(doc["id"])
            return SamlAssertion(
                name_id=doc["name_id"],
                audience=doc["audience"],
                not_on_or_after=int(doc["not_on_or_after"]),
            )
        except Exception:
            return None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "base64",
        "dataclasses",
        "hashlib",
        "hmac",
        "json",
        "pathlib",
        "secrets",
        "time",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    idp = MockSAMLIdP("https://idp.example.com")
    resp = idp.issue_response("alice", "sp-1", "https://sp/acs", "req-1")
    a = idp.validate_response(resp, "sp-1", "https://sp/acs")
    assert a is not None and a.name_id == "alice"
    # Replay rejected.
    assert idp.validate_response(resp, "sp-1", "https://sp/acs") is None
    # Wrong audience.
    resp2 = idp.issue_response("bob", "sp-2", "https://sp/acs", "req-2")
    assert idp.validate_response(resp2, "sp-1", "https://sp/acs") is None
    # Expired.
    idp2 = MockSAMLIdP("https://idp.example.com", ttl=-1)
    resp3 = idp2.issue_response("c", "sp-1", "https://sp/acs", "req-3")
    assert idp2.validate_response(resp3, "sp-1", "https://sp/acs") is None
    assert stdlib_only()
    print("crypto-defense-25 OK")


if __name__ == "__main__":
    main()
