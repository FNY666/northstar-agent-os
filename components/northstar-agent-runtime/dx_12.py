"""DX-12: Autocomplete (mock), Simulated.

Prefix completion over a symbol table: results ranked by
(1) exact prefix match, (2) substring match, (3) alphabetical.
Optional fuzzy mode matches subsequence.  Deterministic ordering.

Fail-closed: non-string prefix raises; unknown symbols are simply
not suggested (no hallucinated completions).

What this IS: deterministic ranking over a known symbol set.
What this IS NOT: not a semantic/ML completer.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

#: Module version.
DX12_COMPLETE_VERSION = "dx-autocomplete.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-autocomplete.v1"


class CompleteError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Completion:
    label: str
    kind: str = "symbol"
    detail: str = ""


def _is_subsequence(needle: str, haystack: str) -> bool:
    it = iter(haystack)
    return all(ch in it for ch in needle)


class Completer:
    """Mock completer over a static symbol table."""

    def __init__(self, symbols: Optional[Dict[str, str]] = None) -> None:
        # symbol -> kind
        self._symbols: Dict[str, str] = dict(symbols or {})

    def add(self, symbol: str, kind: str = "symbol", detail: str = "") -> None:
        if not symbol:
            raise CompleteError("symbol required")
        self._symbols[symbol] = kind

    def complete(
        self,
        prefix: str,
        *,
        limit: int = 10,
        fuzzy: bool = False,
    ) -> List[Completion]:
        """Return ranked completions.  Never invents symbols."""
        if not isinstance(prefix, str):
            raise CompleteError("prefix must be str")
        if limit <= 0:
            raise CompleteError("limit must be positive")
        scored: List[tuple] = []
        for sym, kind in self._symbols.items():
            if sym.startswith(prefix):
                rank = 0
            elif prefix in sym:
                rank = 1
            elif fuzzy and _is_subsequence(prefix, sym):
                rank = 2
            else:
                continue
            scored.append((rank, sym, kind))
        scored.sort(key=lambda t: (t[0], t[1]))
        return [Completion(label=s, kind=k) for _, s, k in scored[:limit]]


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    c = Completer({"print": "builtin", "printf": "function", "priority": "variable", "len": "builtin"})
    out = c.complete("pr")
    assert [x.label for x in out] == ["print", "printf", "priority"]  # prefix, prefix, substring... check order
    out = c.complete("pr", limit=2)
    assert len(out) == 2
    out = c.complete("ptf", fuzzy=True)
    assert [x.label for x in out] == ["printf"]
    out = c.complete("ptf", fuzzy=False)
    assert out == []
    out = c.complete("zzz")
    assert out == []  # no hallucination
    try:
        c.complete(123)  # type: ignore
        raise AssertionError("should raise")
    except CompleteError:
        pass
    assert stdlib_only()
    print("dx_12 OK: ranking, fuzzy, limit, no hallucination")


if __name__ == "__main__":
    main()
