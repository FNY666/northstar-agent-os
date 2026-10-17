"""Independent start/end security scan gate for coding runs.

The gate uses the same bounded, offline scanner as ``SecurityScan``. It compares
grouped findings from the workspace before and after the run, so existing issues
do not block work. An incomplete scan fails closed because it cannot establish
that the run introduced no findings.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from coding_acceptance import MAX_REPAIR_ATTEMPTS


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
MAX_FINDING_DETAILS = 50
MAX_SKIPPED_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_SKIPPED_BYTES = 256 * 1024 * 1024


class SecurityGateError(ValueError):
    """Invalid gate configuration or unusable workspace scan."""


@dataclass(frozen=True)
class SecurityGateConfig:
    """Run policy for the opt-in, read-only security gate."""

    fail_on: str = "high"
    max_files: int = 4_000
    max_file_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.fail_on, str) or self.fail_on not in SEVERITY_RANK:
            raise SecurityGateError("security gate fail_on must be critical, high, medium, low, or none")
        if isinstance(self.max_files, bool) or not isinstance(self.max_files, int) or not 1 <= self.max_files <= 10_000:
            raise SecurityGateError("security gate max_files must be from 1 to 10000")
        if isinstance(self.max_file_bytes, bool) or not isinstance(self.max_file_bytes, int) or not 1 <= self.max_file_bytes <= 1024 * 1024:
            raise SecurityGateError("security gate max_file_bytes must be from 1 to 1048576")

    def as_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on,
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
        }


class SecurityGate:
    """Compare pre-run and post-run findings under one fixed scan scope."""

    max_repair_attempts = MAX_REPAIR_ATTEMPTS

    def __init__(self, root: Path | str, config: SecurityGateConfig) -> None:
        if not isinstance(config, SecurityGateConfig):
            raise SecurityGateError("security_gate must be a SecurityGateConfig")
        self.root = Path(root).resolve()
        self.config = config
        self._before: dict[str, Any] | None = None
        self._before_error: str | None = None
        self._before_skipped_fingerprints: dict[str, str] | None = None
        self._snapshot_taken = False

    def _scan(self) -> dict[str, Any]:
        from security_cli import _scan_root

        return _scan_root(
            self.root,
            max_files=self.config.max_files,
            max_file_bytes=self.config.max_file_bytes,
            fail_on="none",
            # The gate compares grouped counts only; keeping every detailed
            # finding would add memory cost without changing the verdict.
            max_findings=0,
        )

    @staticmethod
    def _complete(summary: dict[str, Any]) -> bool:
        return not summary.get("file_limit_reached")

    def _fingerprint_skipped(self, summary: dict[str, Any]) -> dict[str, str] | None:
        """Hash skipped candidates within a separate bounded read budget.

        A pre-existing oversized or non-UTF-8 file need not block a delta gate
        when its bytes are unchanged. New or modified skipped paths remain an
        incomplete scan and fail closed.
        """
        from tools import ToolAccessError, ToolSandbox

        fingerprints: dict[str, str] = {}
        total = 0
        sandbox = ToolSandbox(self.root)
        for relative in summary.get("_skipped_paths", ()):
            try:
                path = sandbox.resolve(str(relative), must_exist=True)
                if path.is_symlink() or not path.is_file():
                    return None
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
                with os.fdopen(descriptor, "rb") as handle:
                    before = os.fstat(handle.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        return None
                    size = before.st_size
                    if size > MAX_SKIPPED_FILE_BYTES or total + size > MAX_TOTAL_SKIPPED_BYTES:
                        return None
                    digest = hashlib.sha256()
                    consumed = 0
                    while True:
                        chunk = handle.read(min(64 * 1024, MAX_SKIPPED_FILE_BYTES - consumed + 1))
                        if not chunk:
                            break
                        consumed += len(chunk)
                        if consumed > MAX_SKIPPED_FILE_BYTES or total + consumed > MAX_TOTAL_SKIPPED_BYTES:
                            return None
                        digest.update(chunk)
                    after = os.fstat(handle.fileno())
                    if (
                        consumed != size
                        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    ):
                        return None
                total += consumed
                fingerprints[str(relative)] = digest.hexdigest()
            except (OSError, ToolAccessError, ValueError):
                return None
        return fingerprints

    @staticmethod
    def _groups(summary: dict[str, Any]) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
        raw_groups = summary.get("_finding_groups", ())
        groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for item in raw_groups:
            if not isinstance(item, dict):
                continue
            identity = (
                str(item.get("path", "")),
                str(item.get("tool", "")),
                str(item.get("rule", "")),
                str(item.get("severity", "")),
                str(item.get("message", "")),
            )
            groups[identity] = item
        return groups

    def snapshot(self) -> None:
        """Record the scan baseline before the first model turn."""
        if self._snapshot_taken:
            return
        self._snapshot_taken = True
        try:
            self._before = self._scan()
            self._before_skipped_fingerprints = self._fingerprint_skipped(self._before)
            self._before_error = None
        except Exception as error:  # noqa: BLE001 - surfaced as a failed gate verdict
            self._before = None
            self._before_skipped_fingerprints = None
            self._before_error = type(error).__name__

    def evaluate(self) -> dict[str, Any]:
        """Return a bounded, JSON-safe pass/fail receipt."""
        try:
            current = self._scan()
            current_skipped_fingerprints = self._fingerprint_skipped(current)
        except Exception as error:  # noqa: BLE001 - no scan failure may become success
            return {
                "kind": "security_gate",
                "ok": False,
                "status": "error",
                "coverage": "error",
                "fail_on": self.config.fail_on,
                "detail": f"post-run scan failed ({type(error).__name__})",
            }

        if self._before is None:
            before_reason = self._before_error or "baseline was not captured"
            return {
                "kind": "security_gate",
                "ok": False,
                "status": "error",
                "coverage": "error",
                "fail_on": self.config.fail_on,
                "detail": f"pre-run scan failed ({before_reason})",
                "files_scanned_after": current.get("files_scanned", 0),
            }

        before_complete = self._complete(self._before)
        after_complete = self._complete(current)
        before_skips = self._before_skipped_fingerprints
        skipped_changed = before_skips is None or current_skipped_fingerprints is None
        unverified_paths: set[str] = set()
        if skipped_changed:
            unverified_paths.update(str(path) for path in self._before.get("_skipped_paths", ()))
            unverified_paths.update(str(path) for path in current.get("_skipped_paths", ()))
        else:
            before_skipped_paths = set(before_skips)
            after_skipped_paths = set(current_skipped_fingerprints)
            unverified_paths = {
                path for path in after_skipped_paths
                if path not in before_skipped_paths
            }
            changed_skips = {
                path for path in after_skipped_paths
                if path in before_skipped_paths
                and before_skips[path] != current_skipped_fingerprints[path]
            }
            skipped_changed = bool(unverified_paths or changed_skips)
            unverified_paths.update(changed_skips)
        if not before_complete or not after_complete or skipped_changed:
            reasons = []
            for label, summary in (("baseline", self._before), ("post-run", current)):
                if summary.get("file_limit_reached"):
                    reasons.append(f"{label} reached the file limit")
            if skipped_changed:
                reasons.append("a skipped or oversized file was added, changed, or could not be fingerprinted")
            return {
                "kind": "security_gate",
                "ok": False,
                "status": "incomplete",
                "coverage": "incomplete",
                "fail_on": self.config.fail_on,
                "detail": "; ".join(reasons) or "scan coverage was incomplete",
                "files_scanned_before": self._before.get("files_scanned", 0),
                "files_scanned_after": current.get("files_scanned", 0),
                "files_skipped_before": self._before.get("files_skipped", 0),
                "files_skipped_after": current.get("files_skipped", 0),
                "unverified_paths": sorted(unverified_paths)[:MAX_FINDING_DETAILS],
            }

        before = self._groups(self._before)
        after = self._groups(current)
        additions: list[dict[str, Any]] = []
        threshold_findings = 0
        for identity in sorted(set(before) | set(after)):
            old_count = int(before.get(identity, {}).get("count", 0))
            new_count = int(after.get(identity, {}).get("count", 0))
            added = new_count - old_count
            if added <= 0:
                continue
            item = after[identity]
            additions.append({**item, "count": added})
            severity = str(item.get("severity", "none"))
            if (
                self.config.fail_on != "none"
                and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK[self.config.fail_on]
            ):
                threshold_findings += added

        additions.sort(key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity", "none")), 0),
            str(item.get("path", "")),
            int(item.get("line", 0)),
            str(item.get("rule", "")),
        ))
        ok = threshold_findings == 0
        return {
            "kind": "security_gate",
            "ok": ok,
            "status": "passed" if ok else "failed",
            "fail_on": self.config.fail_on,
            "files_scanned_before": self._before.get("files_scanned", 0),
            "files_scanned_after": current.get("files_scanned", 0),
            "files_skipped_before": self._before.get("files_skipped", 0),
            "files_skipped_after": current.get("files_skipped", 0),
            "coverage": "unchanged_skips" if self._before.get("files_skipped") or current.get("files_skipped") else "complete",
            "baseline_findings": self._before.get("findings_count", 0),
            "current_findings": current.get("findings_count", 0),
            "new_findings": sum(int(item["count"]) for item in additions),
            "threshold_findings": threshold_findings,
            "new": additions[:MAX_FINDING_DETAILS],
            "details_truncated": len(additions) > MAX_FINDING_DETAILS,
            "detail": (
                f"{threshold_findings} new finding(s) meet fail_on={self.config.fail_on}"
                if threshold_findings else "no new findings meet the configured severity threshold"
            ),
        }


__all__ = ["SecurityGate", "SecurityGateConfig", "SecurityGateError"]
