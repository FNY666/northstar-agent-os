"""Runtime defense 08: no-new-privileges flag, Simulated.

Config enforcing PR_SET_NO_NEW_PRIVS: once set, execve cannot grant new
privileges (setuid/setgid/file caps are ignored).  The flag is
one-way: this config cannot unset it.

What this IS: no_new_privs enforcement flag config.
What this IS NOT: the actual prctl(2) call.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Module version.
RUNTIME_DEFENSE_08_VERSION = "runtime-defense-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-08.v1"


class NoNewPrivsError(Exception):
    """Fail-closed."""


@dataclass
class NoNewPrivsConfig:
    """One-way no-new-privileges flag."""

    enabled: bool = True
    _locked: bool = False

    def enable(self) -> None:
        """Enable the flag.  Can be called at setup."""
        if self._locked:
            raise NoNewPrivsError("already locked: cannot re-enable")
        self.enabled = True

    def lock(self) -> None:
        """Lock the config: no further changes allowed (one-way)."""
        self._locked = True

    def disable(self) -> None:
        """Always refused: the flag cannot be turned off."""
        raise NoNewPrivsError("no_new_privs cannot be disabled: fail-closed")

    def prctl_value(self) -> int:
        """Value for prctl(PR_SET_NO_NEW_PRIVS, ...)."""
        return 1 if self.enabled else 0


def build_config() -> NoNewPrivsConfig:
    """Default: enabled and locked."""
    cfg = NoNewPrivsConfig(enabled=True)
    cfg.lock()
    return cfg


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    cfg = build_config()
    assert cfg.enabled is True
    assert cfg.prctl_value() == 1

    # Disable always refused.
    try:
        cfg.disable()
        raise AssertionError("should raise")
    except NoNewPrivsError:
        pass

    # Re-enable after lock refused.
    try:
        cfg.enable()
        raise AssertionError("should raise")
    except NoNewPrivsError:
        pass

    # Unlocked config can enable then lock.
    cfg2 = NoNewPrivsConfig(enabled=False)
    cfg2.enable()
    assert cfg2.enabled is True
    cfg2.lock()

    assert stdlib_only()
    print("runtime-defense-08 OK: one-way flag, lock, fail-closed, stdlib")


if __name__ == "__main__":
    main()
