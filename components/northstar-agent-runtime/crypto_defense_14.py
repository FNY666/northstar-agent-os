"""Crypto Defense 14: PIR for lookups (mock), Simulated.

Mock Private Information Retrieval: client queries a database without
revealing which item they want.  Mock uses trivial PIR (download all)
for interface shape.

What this IS: private query API.
What this IS NOT: real PIR cryptography.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Dict, List, Optional

#: Module version.
CRYPTO_DEFENSE_14_VERSION = "crypto-defense-14.v1"
SCHEMA_PIN = "northstar.crypto-defense-14.v1"


class PirError(Exception):
    """Fail-closed."""


class MockPirServer:
    """PIR server holding database (mock)."""

    def __init__(self, db: Dict[int, bytes]) -> None:
        if not db:
            raise PirError("db required")
        self._db = dict(db)

    def get_all(self) -> Dict[int, bytes]:
        """Trivial PIR: return all (client picks locally)."""
        return dict(self._db)

    def size(self) -> int:
        return len(self._db)


class MockPirClient:
    """PIR client (mock: trivial PIR)."""

    def query(self, index: int, server: MockPirServer) -> Optional[bytes]:
        """Query index without server learning which (mock).

        Trivial PIR: download all, pick locally.  Server sees only
        that a query happened, not which index.
        """
        if not isinstance(index, int) or index < 0:
            raise PirError("bad index")
        all_data = server.get_all()
        # Client-side selection (server doesn't know which).
        return all_data.get(index)

    def batch_query(
        self, indices: List[int], server: MockPirServer
    ) -> Dict[int, Optional[bytes]]:
        """Batch query (mock)."""
        all_data = server.get_all()
        return {i: all_data.get(i) for i in indices}


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    db = {0: b"item0", 1: b"item1", 2: b"item2"}
    server = MockPirServer(db)
    client = MockPirClient()
    assert client.query(1, server) == b"item1"
    assert client.query(99, server) is None
    batch = client.batch_query([0, 2], server)
    assert batch == {0: b"item0", 2: b"item2"}
    assert server.size() == 3
    try:
        client.query(-1, server)
        raise AssertionError("should raise")
    except PirError:
        pass
    assert stdlib_only()
    print("crypto-defense-14 OK")


if __name__ == "__main__":
    main()
