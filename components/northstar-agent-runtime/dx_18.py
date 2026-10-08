"""DX-18: Formatters (mock), Simulated.

Named formatter registry. `format_text(name, text)` applies the
registered pure-string transform; idempotence is probed at registration
(format(format(x)) == format(x) on canned inputs). Unknown formatter
names raise.

What this IS: a registry of pure string transforms with idempotence check.
What this IS NOT: not a real code formatter.
"""

from __future__ import annotations

import ast
from typing import Callable, Dict, List

#: Module version.
DX18_FORMATTERS_VERSION = "dx-formatters.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-formatters.v1"


class FormattersError(Exception):
    """Fail-closed."""


#: Idempotence probe inputs used at registration.
_PROBES = ("", "x", "a  b\n", "  indented\n", "a\n\nb\n")


class FormatterRegistry:
    """Name -> pure string transform, idempotence-checked."""

    def __init__(self) -> None:
        self._fmts: Dict[str, Callable[[str], str]] = {}

    def register(self, name: str, fn: Callable[[str], str]) -> None:
        if not name or not name.strip():
            raise FormattersError("name required")
        if name in self._fmts:
            raise FormattersError(f"duplicate formatter '{name}'")
        if not callable(fn):
            raise FormattersError("fn must be callable")
        try:
            for probe in _PROBES:
                once = fn(probe)
                if not isinstance(once, str):
                    raise FormattersError("formatter must return str")
                if fn(once) != once:
                    raise FormattersError(
                        f"formatter '{name}' not idempotent on {probe!r}"
                    )
        except FormattersError:
            raise
        except Exception as e:
            raise FormattersError(f"formatter '{name}' probe failed: {e}")
        self._fmts[name] = fn

    def format_text(self, name: str, text: str) -> str:
        if name not in self._fmts:
            raise FormattersError(f"unknown formatter '{name}'")
        if not isinstance(text, str):
            raise FormattersError("text must be str")
        return self._fmts[name](text)

    @property
    def names(self) -> List[str]:
        return sorted(self._fmts)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    reg = FormatterRegistry()
    reg.register("collapse", lambda s: " ".join(s.split()))
    assert reg.format_text("collapse", "a   b\n") == "a b"
    assert reg.format_text("collapse", "") == ""
    try:
        reg.format_text("nope", "x")
        raise AssertionError("should raise")
    except FormattersError:
        pass
    try:
        reg.register("grow", lambda s: s + " ")  # not idempotent
        raise AssertionError("should raise")
    except FormattersError:
        pass
    try:
        reg.register("collapse", str.strip)  # duplicate
        raise AssertionError("should raise")
    except FormattersError:
        pass
    assert reg.names == ["collapse"]
    assert stdlib_only()
    print("dx_18 OK: register, format, unknown/non-idempotent rejected")


if __name__ == "__main__":
    main()
