"""Locate the archived live runs, or say why the archive is unavailable.

These tests replay real runs that were archived outside the repository. On a
machine that has the archive they run for real; everywhere else they are
skipped rather than failed, because a missing archive is a missing input, not
a broken guard. The environment variable lets a CI job point at its own copy.
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ARCHIVE_ROOT = Path("/var/minis/shared/northstar-live-runs")


def archive_root() -> Path:
    """The archive root, overridable through ``NORTHSTAR_LIVE_RUNS``."""
    return Path(os.environ.get("NORTHSTAR_LIVE_RUNS", str(DEFAULT_ARCHIVE_ROOT)))


def archive_unavailable_reason(*required: Path | str) -> str | None:
    """Why the archive cannot be used, or None when it can."""
    root = archive_root()
    if not root.is_dir():
        return f"archived live runs are not available at {root}"
    missing = [item for item in required if not (root / item).exists()]
    if missing:
        listed = ", ".join(str(item) for item in missing)
        return f"archived live runs are missing {listed} under {root}"
    return None
