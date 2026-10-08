"""obs_16: pprof text profile format (mock data format), Simulated.

Emits and parses a simplified pprof-like text format: a header block
with a magic line and a sample_type line, a samples section holding
folded stacks with values ("a;b;c value"), and a location table mapping
numeric ids to function/file/line rows.  Mock: profiles are entirely
caller-supplied; no real profiler ever runs.

Fail-closed: malformed headers, samples, or locations raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

OBS16_VERSION = "obs-16.v1"
SCHEMA_PIN = "northstar.obs-16.v1"

MAGIC = "# northstar.obs-16.v1"


class Obs16Error(Exception):
    """Fail-closed."""


def validate_header(lines: List[str]) -> str:
    """Validate the header of a pprof-like document.

    The first line must be the magic line and a 'sample_type: <...>'
    line must be present.  Returns the sample_type string.
    """
    if not isinstance(lines, list) or not all(isinstance(l, str) for l in lines):
        raise Obs16Error("lines must be a list of str")
    if not lines or lines[0].strip() != MAGIC:
        raise Obs16Error("bad magic line")
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("sample_type:"):
            sample_type = stripped.split(":", 1)[1].strip()
            if not sample_type:
                raise Obs16Error("empty sample_type")
            return sample_type
    raise Obs16Error("missing sample_type line")


def emit_pprof(
    samples: List[Tuple[List[str], int]],
    sample_type: str = "cpu nanoseconds",
) -> str:
    """Emit a simplified pprof-like text document.

    samples is [(frames, value), ...]; a location table is generated
    from unique frames in order of first appearance.
    """
    if not isinstance(samples, list):
        raise Obs16Error("samples must be list")
    if not isinstance(sample_type, str) or not sample_type.strip():
        raise Obs16Error("sample_type must be non-empty str")
    order: List[str] = []
    seen = set()
    parsed: List[Tuple[List[str], int]] = []
    for item in samples:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise Obs16Error("each sample must be (frames, value)")
        frames, value = item
        if not isinstance(frames, list) or not frames:
            raise Obs16Error("frames must be non-empty list")
        for f in frames:
            if not isinstance(f, str) or not f or ";" in f:
                raise Obs16Error("frames must be non-empty strings without ';'")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise Obs16Error("value must be non-negative int")
        for f in frames:
            if f not in seen:
                seen.add(f)
                order.append(f)
        parsed.append((frames, value))
    lines = [MAGIC, f"sample_type: {sample_type.strip()}", "samples:"]
    for frames, value in parsed:
        lines.append(";".join(frames) + f" {value}")
    lines.append("locations:")
    for idx, func in enumerate(order, start=1):
        lines.append(f"{idx} {func} unknown 0")
    return "\n".join(lines)


def parse_pprof(text: str) -> Dict:
    """Parse a simplified pprof-like document.  Raises on malformed."""
    if not isinstance(text, str):
        raise Obs16Error("text must be str")
    lines = text.splitlines()
    sample_type = validate_header(lines)
    samples: List[Dict] = []
    locations: List[Dict] = []
    section: Optional[str] = None
    for line in lines[1:]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("sample_type:"):
            continue
        if s == "samples:":
            if section is not None:
                raise Obs16Error("duplicate samples section")
            section = "samples"
            continue
        if s == "locations:":
            if section != "samples":
                raise Obs16Error("locations section before samples section")
            section = "locations"
            continue
        if section == "samples":
            if " " not in s:
                raise Obs16Error(f"malformed sample line '{s}'")
            stack_part, value_part = s.rsplit(" ", 1)
            try:
                value = int(value_part)
            except ValueError:
                raise Obs16Error(f"bad value in '{s}'")
            if value < 0:
                raise Obs16Error(f"bad value in '{s}'")
            frames = stack_part.split(";")
            if not all(frames):
                raise Obs16Error(f"empty frame in '{s}'")
            samples.append({"frames": frames, "value": value})
        elif section == "locations":
            parts = s.split()
            if len(parts) != 4:
                raise Obs16Error(f"malformed location line '{s}'")
            lid, func, file, lineno = parts
            try:
                lid_i, lineno_i = int(lid), int(lineno)
            except ValueError:
                raise Obs16Error(f"bad location numbers in '{s}'")
            if lid_i < 1 or lineno_i < 0 or not func:
                raise Obs16Error(f"bad location row in '{s}'")
            locations.append(
                {"id": lid_i, "func": func, "file": file, "line": lineno_i}
            )
        else:
            raise Obs16Error(f"unexpected line outside sections '{s}'")
    if section != "locations":
        raise Obs16Error("missing locations section")
    return {
        "schema": SCHEMA_PIN,
        "sample_type": sample_type,
        "samples": samples,
        "locations": locations,
    }


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
    samples = [(["main", "work", "io"], 1000), (["main", "idle"], 300)]
    text = emit_pprof(samples)
    assert text.startswith(MAGIC + "\nsample_type: cpu nanoseconds\nsamples:")
    assert validate_header(text.splitlines()) == "cpu nanoseconds"
    doc = parse_pprof(text)
    assert doc["schema"] == SCHEMA_PIN
    assert doc["samples"] == [
        {"frames": ["main", "work", "io"], "value": 1000},
        {"frames": ["main", "idle"], "value": 300},
    ]
    assert [loc["func"] for loc in doc["locations"]] == ["main", "work", "io", "idle"]
    try:
        parse_pprof("not a profile\n")
        raise AssertionError("should raise")
    except Obs16Error:
        pass
    try:
        emit_pprof([(["a", ""], 1)])
        raise AssertionError("should raise")
    except Obs16Error:
        pass
    try:
        validate_header([MAGIC])
        raise AssertionError("should raise")
    except Obs16Error:
        pass
    assert stdlib_only()
    print("obs_16 OK")


if __name__ == "__main__":
    main()
