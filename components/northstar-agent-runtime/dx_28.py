"""DX-28: Release automation (mock), Simulated.

Fixed ordered pipeline: validate -> tag -> publish -> announce.
`plan(version)` validates a semver `X.Y.Z` and returns the ordered
steps. `complete(step)` enforces order and returns the next step, or
None when the release is done. Out-of-order completion raises.

What this IS: an ordered checklist state machine.
What this IS NOT: not performing real releases.
"""

from __future__ import annotations

import ast
import re
from typing import List, Optional

#: Module version.
DX28_RELEASE_VERSION = "dx-release.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-release.v1"

#: Ordered pipeline steps.
STEPS = ("validate", "tag", "publish", "announce")

_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


class ReleaseError(Exception):
    """Fail-closed."""


class Release:
    """Ordered release checklist."""

    def __init__(self, version: str) -> None:
        if not isinstance(version, str) or not _SEMVER.match(version):
            raise ReleaseError(f"version must be X.Y.Z, got {version!r}")
        self._version = version
        self._done: List[str] = []

    @property
    def version(self) -> str:
        return self._version

    def plan(self) -> List[str]:
        return list(STEPS)

    def next_step(self) -> Optional[str]:
        for step in STEPS:
            if step not in self._done:
                return step
        return None

    def complete(self, step: str) -> Optional[str]:
        expected = self.next_step()
        if expected is None:
            raise ReleaseError("release already complete")
        if step != expected:
            raise ReleaseError(
                f"expected step '{expected}', got '{step}'"
            )
        self._done.append(step)
        return self.next_step()

    @property
    def done(self) -> bool:
        return self.next_step() is None


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    rel = Release("1.2.3")
    assert rel.plan() == ["validate", "tag", "publish", "announce"]
    assert rel.complete("validate") == "tag"
    try:
        rel.complete("publish")  # skip tag
        raise AssertionError("should raise")
    except ReleaseError:
        pass
    assert rel.complete("tag") == "publish"
    assert rel.complete("publish") == "announce"
    assert rel.complete("announce") is None
    assert rel.done is True
    try:
        rel.complete("announce")
        raise AssertionError("should raise")
    except ReleaseError:
        pass
    try:
        Release("1.2")
        raise AssertionError("should raise")
    except ReleaseError:
        pass
    try:
        Release("v1.2.3")
        raise AssertionError("should raise")
    except ReleaseError:
        pass
    assert stdlib_only()
    print("dx_28 OK: semver validation, ordered steps, skip rejected")


if __name__ == "__main__":
    main()
