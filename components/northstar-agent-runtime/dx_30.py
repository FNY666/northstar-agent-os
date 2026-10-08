"""DX-30: Plugin system (mock), Simulated.

Plugins subscribe to named hooks; `emit(hook, payload)` delivers to
subscribers in registration order and returns delivery records.
Subscribing an unknown plugin raises; emitting an unknown hook returns
an empty list (broadcast, not an error).

What this IS: explicit pub/sub dispatch for UI plumbing.
What this IS NOT: not loading real plugin code.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List

#: Module version.
DX30_PLUGINS_VERSION = "dx-plugins.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-plugins.v1"


class PluginsError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Delivery:
    plugin: str
    hook: str


class PluginBus:
    """Explicit plugin pub/sub bus."""

    def __init__(self) -> None:
        self._plugins: List[str] = []
        self._subs: Dict[str, List[str]] = {}

    def register_plugin(self, name: str) -> None:
        if not name or not name.strip():
            raise PluginsError("plugin name required")
        if name in self._plugins:
            raise PluginsError(f"duplicate plugin '{name}'")
        self._plugins.append(name)

    def subscribe(self, name: str, hook: str) -> None:
        if name not in self._plugins:
            raise PluginsError(f"unknown plugin '{name}'")
        if not hook or not hook.strip():
            raise PluginsError("hook required")
        subs = self._subs.setdefault(hook, [])
        if name in subs:
            raise PluginsError(f"'{name}' already subscribed to '{hook}'")
        subs.append(name)

    def unsubscribe(self, name: str, hook: str) -> None:
        subs = self._subs.get(hook, [])
        if name not in subs:
            raise PluginsError(f"'{name}' not subscribed to '{hook}'")
        subs.remove(name)

    def emit(self, hook: str, payload: Any = None) -> List[Delivery]:
        if not hook or not hook.strip():
            raise PluginsError("hook required")
        ordered = [p for p in self._plugins if p in self._subs.get(hook, [])]
        return [Delivery(plugin=p, hook=hook) for p in ordered]

    @property
    def plugins(self) -> List[str]:
        return list(self._plugins)

    def hooks(self, name: str) -> List[str]:
        if name not in self._plugins:
            raise PluginsError(f"unknown plugin '{name}'")
        return sorted(h for h, subs in self._subs.items() if name in subs)


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
    bus = PluginBus()
    bus.register_plugin("git")
    bus.register_plugin("lint")
    bus.subscribe("lint", "on_save")
    bus.subscribe("git", "on_save")
    got = bus.emit("on_save")
    # registration order, not subscription order
    assert [(d.plugin, d.hook) for d in got] == [
        ("git", "on_save"), ("lint", "on_save")
    ]
    assert bus.emit("on_idle") == []
    bus.unsubscribe("git", "on_save")
    assert [d.plugin for d in bus.emit("on_save")] == ["lint"]
    try:
        bus.subscribe("nope", "on_save")
        raise AssertionError("should raise")
    except PluginsError:
        pass
    try:
        bus.unsubscribe("lint", "on_idle")
        raise AssertionError("should raise")
    except PluginsError:
        pass
    assert bus.hooks("lint") == ["on_save"]
    assert stdlib_only()
    print("dx_30 OK: pub/sub order, unknown-hook broadcast, validation")


if __name__ == "__main__":
    main()
