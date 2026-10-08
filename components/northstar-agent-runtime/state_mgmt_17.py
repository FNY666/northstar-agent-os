"""State 17: Chandy-Lamport distributed snapshot (mock), Simulated.

Mock of the Chandy-Lamport marker algorithm over in-process channels:
- initiator records local state, sends MARKER on all outgoing channels
- on first MARKER receipt: record local state, start recording the
  channel the marker arrived on
- on subsequent MARKERs: stop recording that channel

Each Channel is a FIFO list of messages.  The snapshot captures
local state + in-flight messages per channel.

Mock: synchronous in-process delivery; models the algorithm's state
machine, not real networking.

Fail-closed: unknown channel, double marker initiation, or recording
on a non-existent channel raises.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List


MODULE_VERSION = "state-mgmt-17.v1"
SCHEMA_PIN = "northstar.state-mgmt-17.v1"


class ChandyLamportError(Exception):
    pass


@dataclass
class Channel:
    name: str
    messages: List[str] = field(default_factory=list)
    recording: bool = False
    recorded: List[str] = field(default_factory=list)


class CLNode:
    """One participant in the Chandy-Lamport snapshot."""

    def __init__(self, node_id: str, local_state: str = "") -> None:
        if not node_id:
            raise ChandyLamportError("node_id required")
        self.node_id = node_id
        self.local_state = local_state
        self.channels: Dict[str, Channel] = {}
        self.recorded_state: str | None = None
        self._marker_seen = False

    def add_channel(self, name: str) -> Channel:
        if name in self.channels:
            raise ChandyLamportError(f"channel {name} exists")
        ch = Channel(name)
        self.channels[name] = ch
        return ch

    def initiate(self) -> List[str]:
        """Start a snapshot; returns markers to send on each channel."""
        if self._marker_seen:
            raise ChandyLamportError("snapshot already in progress")
        self._marker_seen = True
        self.recorded_state = self.local_state
        for ch in self.channels.values():
            ch.recording = True
        return [f"MARKER:{self.node_id}"]

    def receive_marker(self, channel_name: str) -> bool:
        """Handle an incoming marker.  Returns True if this node just
        recorded its state (first marker), False otherwise."""
        ch = self.channels.get(channel_name)
        if ch is None:
            raise ChandyLamportError(f"unknown channel {channel_name}")
        if not self._marker_seen:
            self._marker_seen = True
            self.recorded_state = self.local_state
            # Start recording all incoming channels; the arrival channel
            # is considered empty (marker sent after all prior messages).
            for c in self.channels.values():
                c.recording = c.name != channel_name
            return True
        ch.recording = False  # stop recording this channel
        return False

    def deliver(self, channel_name: str, msg: str) -> None:
        ch = self.channels.get(channel_name)
        if ch is None:
            raise ChandyLamportError(f"unknown channel {channel_name}")
        ch.messages.append(msg)
        if ch.recording:
            ch.recorded.append(msg)


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
    a, b = CLNode("a", "SA"), CLNode("b", "SB")
    a.add_channel("a->b")
    b.add_channel("b->a")
    # In-flight message before snapshot starts.
    b.deliver("b->a", "m1")
    markers = a.initiate()
    assert markers == ["MARKER:a"]
    assert a.recorded_state == "SA"
    # b gets first marker -> records state, keeps recording b->a.
    first = b.receive_marker("b->a")
    assert first is True and b.recorded_state == "SB"
    b.deliver("b->a", "m2")  # arrives after marker -> recorded as in-flight
    assert b.channels["b->a"].recorded == ["m2"]
    # a gets marker back -> stops recording.
    assert a.receive_marker("a->b") is False
    assert a.channels["a->b"].recording is False
    # Double initiate -> fail-closed.
    try:
        a.initiate()
        raise AssertionError("should raise")
    except ChandyLamportError:
        pass
    assert stdlib_only()
    print("state_mgmt_17 OK: marker propagation, in-flight capture, fail-closed")


if __name__ == "__main__":
    main()
