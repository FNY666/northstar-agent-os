"""Canary files: create and verify trip files.

create(name) writes a file with a random token under base_dir and
records its sha256. check(name) re-hashes and reports:
ok / modified / missing. check_all() sweeps every canary.
Legitimate processes never touch these files.

What this IS: real file creation + sha256 verification.

What this IS NOT:
* Not kernel-level monitoring -- poll-based check().
"""

from __future__ import annotations

import ast
import hashlib
import secrets
from pathlib import Path
from typing import Dict, Union

#: Module version.
MONITOR_21_VERSION = "monitor-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-21.v1"


class CanaryError(Exception):
    """Fail-closed."""


def _safe_name(name: str) -> str:
    if not name or not isinstance(name, str):
        raise CanaryError("name required")
    if "/" in name or "\\" in name or ".." in name:
        raise CanaryError(f"unsafe canary name {name!r}")
    if name.startswith("."):
        raise CanaryError("dotfiles not allowed")
    return name


class CanaryFiles:
    """Canary-file manager rooted at base_dir."""

    def __init__(self, base_dir: Union[str, Path]) -> None:
        self._base = Path(base_dir)
        try:
            self._base.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise CanaryError(f"cannot use base_dir: {e}")
        if not self._base.is_dir():
            raise CanaryError("base_dir is not a directory")
        self._hashes: Dict[str, str] = {}

    def create(self, name: str) -> Path:
        """Create a canary file; returns its path."""
        name = _safe_name(name)
        if name in self._hashes:
            raise CanaryError(f"canary {name!r} already exists")
        token = secrets.token_hex(16)
        content = f"canary:{name}:{token}\n".encode("utf-8")
        path = self._base / name
        try:
            path.write_bytes(content)
        except OSError as e:
            raise CanaryError(f"write failed: {e}")
        self._hashes[name] = hashlib.sha256(content).hexdigest()
        return path

    def check(self, name: str) -> str:
        """Return ok / modified / missing."""
        name = _safe_name(name)
        if name not in self._hashes:
            raise CanaryError(f"unknown canary {name!r}")
        path = self._base / name
        if not path.is_file():
            return "missing"
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return "missing"
        return "ok" if digest == self._hashes[name] else "modified"

    def check_all(self) -> Dict[str, str]:
        return {name: self.check(name) for name in self._hashes}

    def remove(self, name: str) -> None:
        name = _safe_name(name)
        if name not in self._hashes:
            raise CanaryError(f"unknown canary {name!r}")
        try:
            (self._base / name).unlink(missing_ok=True)
        except OSError as e:
            raise CanaryError(f"remove failed: {e}")
        del self._hashes[name]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib as _pl

    tree = ast.parse(
        _pl.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "hashlib", "pathlib", "secrets", "tempfile", "typing",
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
    """Self-check."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        cf = CanaryFiles(td)
        p = cf.create("trip1")
        assert p.is_file()
        assert cf.check("trip1") == "ok"
        assert cf.check_all() == {"trip1": "ok"}
        # Tamper.
        p.write_bytes(b"tampered")
        assert cf.check("trip1") == "modified"
        # Delete.
        p.unlink()
        assert cf.check("trip1") == "missing"
        cf.remove("trip1")
        assert cf.check_all() == {}
        for bad in (
            lambda: cf.create("../evil"),
            lambda: cf.create("a/b"),
            lambda: cf.create(".hidden"),
            lambda: cf.create(""),
            lambda: cf.check("ghost"),
            lambda: cf.remove("ghost"),
        ):
            try:
                bad()
                raise AssertionError("should raise")
            except CanaryError:
                pass
    assert stdlib_only()
    print("monitor-21 OK: create, ok/modified/missing, traversal-safe, stdlib")


if __name__ == "__main__":
    main()
