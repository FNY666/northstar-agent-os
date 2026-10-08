"""obs_15: Flame graphs (mock data format), Simulated.

Produces folded-stack format (one line per stack: "a;b;c count")
suitable for flamegraph.pl.  Mock: input stacks are caller-provided,
no real sampling.

Fail-closed: malformed stacks raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

OBS15_VERSION = "obs-15.v1"
SCHEMA_PIN = "northstar.obs-15.v1"


class Obs15Error(Exception):
    """Fail-closed."""


def to_folded(stacks: List[Tuple[List[str], int]]) -> str:
    """Convert [(frames, count), ...] to folded format.

    Each frame list is joined with ';'.  Frames must be non-empty
    strings; counts must be positive ints.
    """
    if not isinstance(stacks, list):
        raise Obs15Error("stacks must be list")
    lines: List[str] = []
    for item in stacks:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise Obs15Error("each stack must be (frames, count)")
        frames, count = item
        if not isinstance(frames, list) or not frames:
            raise Obs15Error("frames must be non-empty list")
        for f in frames:
            if not isinstance(f, str) or not f or ";" in f:
                raise Obs15Error("frames must be non-empty strings without ';'")
        if not isinstance(count, int) or count < 1:
            raise Obs15Error("count must be positive int")
        lines.append(";".join(frames) + f" {count}")
    return "\n".join(lines)


def from_folded(text: str) -> List[Tuple[List[str], int]]:
    """Parse folded format back.  Raises on malformed."""
    if not isinstance(text, str):
        raise Obs15Error("text must be str")
    out: List[Tuple[List[str], int]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if " " not in line:
            raise Obs15Error(f"malformed line '{line}'")
        stack_part, count_part = line.rsplit(" ", 1)
        try:
            count = int(count_part)
        except ValueError:
            raise Obs15Error(f"bad count in '{line}'")
        if count < 1:
            raise Obs15Error(f"bad count in '{line}'")
        frames = stack_part.split(";")
        if not all(frames):
            raise Obs15Error(f"empty frame in '{line}'")
        out.append((frames, count))
    return out


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
    stacks = [(["main", "work", "io"], 10), (["main", "idle"], 3)]
    folded = to_folded(stacks)
    assert folded == "main;work;io 10\nmain;idle 3"
    back = from_folded(folded)
    assert back == stacks
    try:
        to_folded([(["a;b"], 1)])
        raise AssertionError("should raise")
    except Obs15Error:
        pass
    try:
        from_folded("no-count-here")
        raise AssertionError("should raise")
    except Obs15Error:
        pass
    assert stdlib_only()
    print("obs_15 OK")


if __name__ == "__main__":
    main()
