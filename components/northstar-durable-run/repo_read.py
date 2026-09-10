"""Bounded local reads; not an OS sandbox or a secret classifier."""
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path


def _parts(path):
    if not isinstance(path, str) or not path or len(path) > 1024:
        raise ValueError("invalid relative path")
    parts = path.split("/")
    if any(p in {"", ".", ".."} or "\\" in p or "\x00" in p for p in parts):
        raise ValueError("invalid relative path")
    return parts


@dataclass(frozen=True)
class RepoReadResult:
    path: str
    content: str
    size_bytes: int
    digest: str


class RepoReadTool:
    def __init__(self, root, *, allowed_paths=None):
        # Resolve the host-owned root once; model input still walks with O_NOFOLLOW.
        self.root = Path(os.path.realpath(root))
        self.allowed_paths = None if allowed_paths is None else frozenset(allowed_paths)
        if self.allowed_paths is not None:
            for path in self.allowed_paths:
                _parts(path)

    def __call__(self, payload):
        if not isinstance(payload, dict) or set(payload) != {"path", "max_bytes"}:
            raise ValueError("invalid read payload")
        path = payload["path"]
        parts = _parts(path)
        limit = payload["max_bytes"]
        if type(limit) is not int or not 1 <= limit <= 65536:
            raise ValueError("invalid read limit")
        if self.allowed_paths is not None and path not in self.allowed_paths:
            raise ValueError("file is not authorized")
        fd = None
        try:
            # Walk the absolute root too, rejecting symlinks in every component.
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in self.root.parts[1:] + tuple(parts[:-1]):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("file type or size is not permitted")
            raw = bytearray()
            while len(raw) <= limit:
                block = os.read(fd, limit + 1 - len(raw))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(fd)
            if len(raw) > limit or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("file exceeded limit or changed during read")
            content = raw.decode("utf-8")
            return RepoReadResult(path, content, len(raw), "sha256:" + hashlib.sha256(raw).hexdigest())
        except (OSError, UnicodeError):
            raise ValueError("repository file is unavailable") from None
        finally:
            if fd is not None:
                os.close(fd)
