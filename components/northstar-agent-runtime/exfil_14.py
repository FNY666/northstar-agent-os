"""Audio exfiltration detection (mock) (audio-mock), Simulated.

Mock detector for audio-based exfiltration: flags microphone/audio capture without recorded consent.

What this IS: a mock audio-capture consent checker.

What this IS NOT:
* MOCK: analyzes provided event dicts.
* Consent flags are host-provided.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_14_VERSION = "exfil-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-14.v1"


class Exfil14Error(Exception):
    """Fail-closed."""


_AUDIO_APIS = {"getUserMedia:audio", "AudioContext:record", "MediaRecorder:audio"}


def detect_audio_exfil(events: List[Dict[str, Any]]) -> tuple:
    """Detect audio exfil. events: [{api, consented}]. Returns (suspicious, reason)."""
    if not isinstance(events, list):
        raise Exfil14Error("events must be list")
    for e in events:
        if e.get("api") in _AUDIO_APIS and not e.get("consented", False):
            return True, "audio capture without consent: %s" % e["api"]
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    ok, _ = detect_audio_exfil([{"api": "getUserMedia:audio", "consented": True}])
    assert ok is False
    ok, _ = detect_audio_exfil([{"api": "getUserMedia:audio", "consented": False}])
    assert ok is True
    assert stdlib_only()
    print("exfil-14 OK: mock audio, fail-closed")


if __name__ == "__main__":
    main()
