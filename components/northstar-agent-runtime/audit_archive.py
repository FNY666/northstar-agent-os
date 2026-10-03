"""WORM-ready archive packages for audit feeds (``northstar-audit-archive/1``).

An archive package is a directory with a fixed layout::

    <archive>/
      feed.ndjson            # the chained audit feed (audit.ndjson/1)
      anchor-manifest.json   # offline head anchor (audit_chain.anchor_manifest)
      external-anchor.json   # Rekor head anchor (audit_rekor), optional
      archive-manifest.json  # integrity manifest for the package itself

``archive-manifest.json`` pins the sha256 of every file, the head chain
hash, the record count, and the retention window (default 180 days, aligned
with EU AI Act Art. 12's six-month log-retention rule). ``audit
verify-archive`` re-checks everything offline; ``--online`` additionally
re-fetches the Rekor entry.

The package itself is storage-agnostic. For WORM semantics (S3 Object Lock
in COMPLIANCE mode or equivalent), upload the finished directory with
``scripts/s3-worm-upload.sh`` — the script is separate because this module
must stay dependency-free and offline.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ARCHIVE_VERSION = "northstar-audit-archive/1"
FEED_NAME = "feed.ndjson"
ANCHOR_NAME = "anchor-manifest.json"
EXTERNAL_ANCHOR_NAME = "external-anchor.json"
MANIFEST_NAME = "archive-manifest.json"
DEFAULT_RETENTION_DAYS = 180  # EU AI Act Art. 12: six months


@dataclass
class ArchiveResult:
    ok: bool
    reason: str = ""
    files: int = 0
    records: int = 0
    head_chain_hash: str | None = None
    retain_until: str | None = None
    external_anchor: dict[str, Any] = field(default_factory=dict)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_archive(
    directory: str | Path,
    feed_bytes: bytes,
    *,
    session_id: str,
    external_anchor: dict[str, Any] | None = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    created_at: str | None = None,
) -> Path:
    """Write a complete, self-describing archive package directory."""
    from audit_chain import anchor_manifest

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    feed_path = target / FEED_NAME
    feed_path.write_bytes(feed_bytes)

    manifest = anchor_manifest(feed_path)
    (target / ANCHOR_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if external_anchor is not None:
        (target / EXTERNAL_ANCHOR_NAME).write_text(
            json.dumps(external_anchor, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    retain_until = (
        datetime.fromisoformat(created_at.replace("Z", "+00:00")) + timedelta(days=retention_days)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")

    files = {
        FEED_NAME: _sha256_file(feed_path),
        ANCHOR_NAME: _sha256_file(target / ANCHOR_NAME),
    }
    if external_anchor is not None:
        files[EXTERNAL_ANCHOR_NAME] = _sha256_file(target / EXTERNAL_ANCHOR_NAME)
    archive_manifest = {
        "archive": ARCHIVE_VERSION,
        "session_id": session_id,
        "created_at": created_at,
        "retention_days": retention_days,
        "retain_until": retain_until,
        "head_chain_hash": manifest.get("head_chain_hash"),
        "records": manifest.get("records"),
        "files": files,
    }
    (target / MANIFEST_NAME).write_text(
        json.dumps(archive_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return target


def verify_archive(
    directory: str | Path,
    *,
    rekor_url: str | None = None,
    online: bool = False,
    timeout: float = 60.0,
) -> ArchiveResult:
    """Verify an archive package. Offline by default; ``online=True`` also
    re-fetches the Rekor entry. Never raises on malformed input."""
    target = Path(directory)
    manifest_path = target / MANIFEST_NAME
    try:
        archive_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return ArchiveResult(ok=False, reason=f"cannot read {MANIFEST_NAME}: {error}")
    if archive_manifest.get("archive") != ARCHIVE_VERSION:
        return ArchiveResult(ok=False, reason="not a northstar audit archive manifest")

    files = archive_manifest.get("files")
    if not isinstance(files, dict) or not files:
        return ArchiveResult(ok=False, reason="archive manifest lists no files")
    for name, digest in files.items():
        if ".." in Path(name).parts or Path(name).is_absolute():
            return ArchiveResult(ok=False, reason=f"unsafe file name in manifest: {name!r}")
        path = target / name
        if not path.is_file():
            return ArchiveResult(ok=False, reason=f"archived file missing: {name}")
        if _sha256_file(path) != digest:
            return ArchiveResult(ok=False, reason=f"archived file modified: {name}")

    from audit_chain import check_anchor, verify_file

    feed_path = target / FEED_NAME
    chain_result = verify_file(feed_path)
    if not chain_result.ok:
        return ArchiveResult(ok=False, reason=f"feed chain broken: {chain_result.reason}")

    anchor_path = target / ANCHOR_NAME
    try:
        anchor_manifest = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return ArchiveResult(ok=False, reason=f"cannot read {ANCHOR_NAME}: {error}")
    anchor_ok, anchor_note = check_anchor(feed_path, anchor_manifest)
    if not anchor_ok:
        return ArchiveResult(ok=False, reason=f"offline anchor mismatch: {anchor_note}")

    external_state: dict[str, Any] = {"present": False}
    external_path = target / EXTERNAL_ANCHOR_NAME
    if external_path.is_file():
        external_state["present"] = True
        try:
            external_anchor = json.loads(external_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            return ArchiveResult(ok=False, reason=f"cannot read {EXTERNAL_ANCHOR_NAME}: {error}")
        from audit_rekor import RekorError, verify_anchor_in_log, verify_anchor_offline

        head = anchor_manifest.get("head_chain_hash")
        ok, note = verify_anchor_offline(external_anchor, head_chain_hash=head)
        external_state["offline"] = {"ok": ok, "note": note}
        if not ok:
            return ArchiveResult(
                ok=False, reason=f"external anchor invalid: {note}", external_anchor=external_state
            )
        if online:
            try:
                ok, note = verify_anchor_in_log(external_anchor, rekor_url=rekor_url, timeout=timeout)
            except RekorError as error:
                return ArchiveResult(
                    ok=False,
                    reason=f"cannot reach transparency log: {error}",
                    external_anchor=external_state,
                )
            external_state["online"] = {"ok": ok, "note": note}
            if not ok:
                return ArchiveResult(
                    ok=False,
                    reason=f"external anchor not confirmed in log: {note}",
                    external_anchor=external_state,
                )

    return ArchiveResult(
        ok=True,
        reason="archive intact",
        files=len(files),
        records=int(archive_manifest.get("records") or 0),
        head_chain_hash=archive_manifest.get("head_chain_hash"),
        retain_until=archive_manifest.get("retain_until"),
        external_anchor=external_state,
    )
