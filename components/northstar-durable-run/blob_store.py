"""Content-addressed blob area for the durable-run event history.

Claim-check (Temporal's 2MB lesson, applied early): payloads at or above
:data:`CLAIM_CHECK_THRESHOLD_BYTES` never go inline into the JSONL event
history or the ledger sidecar. They are stored once, under their own
``sha256`` digest, in a ``<events>.blobs/`` directory next to the event
file; the event (or sidecar entry) carries only the ``blob_ref``.

The blob area is deliberately dumb: no GC, no compaction, no network.
Missing or corrupt blobs are fail-closed — a ``ValueError`` naming the ref —
never silently treated as empty. The event history stays small and
append-only; large transcript / tool-result bytes live exactly once on disk
and are fetched on demand during fold/replay.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

#: Payloads at or above this size are forced through the blob area instead
#: of being embedded inline. 64 KiB keeps the JSONL history and the ledger
#: sidecar small while staying far below the multi-MB ceilings that forced
#: Temporal to bolt claim-check on after the fact.
CLAIM_CHECK_THRESHOLD_BYTES = 65536

_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _require_ref(value: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise ValueError("blob_ref must be a lowercase sha256 digest")
    return value


class BlobStore:
    """A ``<events>.blobs/`` directory of sha256-named blobs.

    The root is created lazily on the first ``put`` — a run whose payloads
    never cross the claim-check threshold never grows a blob directory.
    Writes are atomic (temp file in the same directory, fsync, rename) so a
    crash mid-write never leaves a half-written blob under its final name.
    """

    def __init__(self, root: str | Path):
        self._root = Path(root).absolute()

    @property
    def root(self) -> Path:
        """Absolute path of the blob directory (may not exist yet)."""
        return self._root

    @staticmethod
    def digest(data: bytes) -> str:
        """The content address for ``data``: ``sha256:<hex>``."""
        if not isinstance(data, bytes):
            raise ValueError("blob data must be bytes")
        return "sha256:" + hashlib.sha256(data).hexdigest()

    def _path_for(self, ref: str) -> Path:
        return self._root / _require_ref(ref)

    def put(self, data: bytes) -> str:
        """Store ``data`` and return its content address.

        Content-addressed: if a blob with the same digest already exists it
        is left untouched (identical bytes, identical name). The write is
        atomic — readers never see a partial blob.
        """
        ref = self.digest(data)
        path = self._path_for(ref)
        if path.exists():
            return ref
        self._root.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="blob.", dir=str(self._root))
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError as error:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ValueError("blob could not be persisted") from error
        return ref

    def get(self, ref: str) -> bytes:
        """Return the blob's bytes, or fail closed.

        Raises ``ValueError`` naming the ref when the blob is missing or
        when its bytes do not hash to the ref (corruption / tampering).
        Never returns empty bytes for a missing blob.
        """
        path = self._path_for(ref)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise ValueError(
                f"blob {ref} is missing from the blob area "
                f"({self._root}): refusing to continue with incomplete history"
            ) from error
        if self.digest(data) != ref:
            raise ValueError(
                f"blob {ref} is corrupt (bytes do not match its content "
                "address): refusing to continue with untrusted history"
            )
        return data

    def exists(self, ref: str) -> bool:
        """Whether a blob file exists for ``ref`` (no integrity check)."""
        return self._path_for(ref).exists()
