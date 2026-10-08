"""PII vault: mask/demask for trust boundary crossing (D6), Simulated.

NER-identified PII is replaced with deterministic type tokens
(PERSON_0, EMAIL_2) before leaving the trust boundary.  The mapping
stays inside; on return, demask by viewer permission.

Two independent mechanisms:
- masking: data doesn't leave (this module)
- zero-retention: model doesn't learn (policy, not code)

What this IS: PII protection at the boundary.

What this IS NOT:
* Not a full NER -- uses regex patterns (host can plug in ML NER).
* The vault is in-memory; production needs sealed storage.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
PII_VAULT_VERSION = "pii-vault.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.pii-vault.v1"


class PiiVaultError(Exception):
    """Fail-closed."""


# Regex patterns for PII (simplified; host can extend).
PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    # API keys (generic).
    "API_KEY": r"\bsk-[A-Za-z0-9]{20,}\b",
}


@dataclass
class Vault:
    """In-memory PII vault keyed by run ID."""

    _store: Dict[str, Dict[str, str]] = None  # run_id -> {token: original}

    def __post_init__(self):
        if self._store is None:
            self._store = {}

    def mask(
        self, text: str, run_id: str
    ) -> Tuple[str, List[str]]:
        """Mask PII in text.  Returns (masked_text, tokens_used).

        Tokens are deterministic per (run_id, type, index).
        """
        if not isinstance(text, str):
            raise PiiVaultError("text must be str")
        if not run_id:
            raise PiiVaultError("run_id required")
        if run_id not in self._store:
            self._store[run_id] = {}
        vault = self._store[run_id]
        masked = text
        tokens_used = []
        counters: Dict[str, int] = {}
        for pii_type, pattern in PATTERNS.items():
            for match in re.finditer(pattern, masked):
                original = match.group(0)
                # Check if already masked (avoid double-masking).
                if original in vault.values():
                    continue
                idx = counters.get(pii_type, 0)
                token = f"{pii_type}_{idx}"
                counters[pii_type] = idx + 1
                # Only mask if not already a token.
                if token not in vault:
                    vault[token] = original
                    tokens_used.append(token)
                # Replace all occurrences.
                masked = masked.replace(original, f"[{token}]")
        return masked, tokens_used

    def demask(
        self, text: str, run_id: str, allowed_types: Optional[List[str]] = None
    ) -> str:
        """Demask tokens.  Only allowed_types are restored.

        If allowed_types is None, all are restored (use with caution).
        """
        if run_id not in self._store:
            return text
        vault = self._store[run_id]
        result = text
        for token, original in vault.items():
            pii_type = token.rsplit("_", 1)[0]
            if allowed_types is not None and pii_type not in allowed_types:
                continue
            result = result.replace(f"[{token}]", original)
        return result

    def clear_run(self, run_id: str) -> None:
        """Clear vault for a run (after completion)."""
        self._store.pop(run_id, None)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    """Self-check."""
    vault = Vault()
    text = "Contact john@example.com or call 555-123-4567"
    masked, tokens = vault.mask(text, "run1")
    assert "john@example.com" not in masked
    assert "[EMAIL_0]" in masked
    assert "[PHONE_0]" in masked
    assert len(tokens) == 2

    # Demask.
    restored = vault.demask(masked, "run1")
    assert "john@example.com" in restored

    # Partial demask (only EMAIL).
    partial = vault.demask(masked, "run1", allowed_types=["EMAIL"])
    assert "john@example.com" in partial
    assert "[PHONE_0]" in partial  # still masked

    # Clear.
    vault.clear_run("run1")
    assert vault.demask(masked, "run1") == masked  # no vault, no demask

    assert stdlib_only()
    print("pii-vault OK: mask, demask, scoped, stdlib")


if __name__ == "__main__":
    main()
