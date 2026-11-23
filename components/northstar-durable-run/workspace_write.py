"""Bounded local writes inside a host-owned root; not an OS sandbox.

The tool is the write counterpart of `repo_read.RepoReadTool`: the root is
resolved once by the host, every path component is walked with `O_NOFOLLOW`,
the payload is an exact `{"path", "content"}` object, and the content is
written through an exclusive temporary file that is fsynced and then renamed
into place, so a reader never observes a partial file.

It does not create identity, isolation, or a secret boundary: anything
writable by the host account inside the root is writable by this tool, so it
must be paired with an allowlist, a private root, and an independent observer.
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from action_gateway import ToolExecutionFailed, ToolRefused

_MAX_PATH = 1024
_MAX_CONTENT = 1_048_576
_TEMP_PREFIX = ".northstar-tmp-"
_CHUNK = 65_536


def _parts(path: object) -> list[str]:
    """Mirror the read-side path rule: relative, no traversal, no separators."""
    if not isinstance(path, str) or not path or len(path) > _MAX_PATH:
        raise ToolRefused("invalid relative path")
    parts = path.split("/")
    if any(p in {"", ".", ".."} or "\\" in p or "\x00" in p for p in parts):
        raise ToolRefused("invalid relative path")
    return parts


@dataclass(frozen=True)
class WorkspaceWriteResult:
    path: str
    size_bytes: int
    digest: str
    created: bool
    previous_digest: str | None

    def as_output(self) -> dict[str, object]:
        """Structured, content-free result for tool-call output envelopes."""
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "digest": self.digest,
            "created": self.created,
            "previous_digest": self.previous_digest,
        }


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class WorkspaceWriteTool:
    def __init__(self, root, *, allowed_paths=None, max_bytes: int = 65_536):
        self.root = Path(os.path.realpath(root))
        if not self.root.is_dir():
            raise ValueError("workspace root must be an existing directory")
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX_CONTENT:
            raise ValueError("max_bytes is invalid")
        self.max_bytes = max_bytes
        self.allowed_paths = None if allowed_paths is None else frozenset(allowed_paths)
        if self.allowed_paths is not None:
            for path in self.allowed_paths:
                _parts(path)

    def __call__(self, payload: object) -> WorkspaceWriteResult:
        if not isinstance(payload, dict) or set(payload) != {"path", "content"}:
            raise ToolRefused("invalid write payload")
        path = payload["path"]
        parts = _parts(path)
        content = payload["content"]
        if not isinstance(content, str):
            raise ToolRefused("content must be a string")
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError:
            raise ToolRefused("content is not encodable UTF-8 text") from None
        if len(raw) > self.max_bytes:
            raise ToolRefused("content exceeds the write bound")
        if self.allowed_paths is not None and path not in self.allowed_paths:
            raise ToolRefused("file is not authorized")

        directory_fd = None
        temporary_fd = None
        temporary_name = None
        try:
            # Walk the host-owned root itself too, rejecting symlinks anywhere.
            directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in self.root.parts[1:] + tuple(parts[:-1]):
                try:
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
                    )
                except FileNotFoundError:
                    os.mkdir(part, mode=0o700, dir_fd=directory_fd)
                    child = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd
                    )
                os.close(directory_fd)
                directory_fd = child
            name = parts[-1]
            created, previous_digest = self._inspect_existing(directory_fd, name)
            temporary_name = _TEMP_PREFIX + os.urandom(8).hex()
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode=0o600,
                dir_fd=directory_fd,
            )
            os.fchmod(temporary_fd, 0o600)
            written = 0
            while written < len(raw):
                written += os.write(temporary_fd, raw[written:])
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.rename(
                temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
            )
            temporary_name = None
            # Make the rename itself durable, not just the file contents.
            os.fsync(directory_fd)
            return WorkspaceWriteResult(
                path=path,
                size_bytes=len(raw),
                digest=_digest_bytes(raw),
                created=created,
                previous_digest=previous_digest,
            )
        except (OSError, UnicodeError):
            # The filesystem was reached and refused mid-write: the effect is
            # not a decision, so the observer must get to decide the outcome.
            raise ToolExecutionFailed("workspace write failed") from None
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if temporary_name is not None and directory_fd is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            if directory_fd is not None:
                os.close(directory_fd)

    def _inspect_existing(self, directory_fd: int, name: str) -> tuple[bool, str | None]:
        """Never overwrite a symlink or a non-regular file; digest what is there."""
        try:
            found = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True, None
        if stat.S_ISLNK(found.st_mode):
            raise ToolRefused("target is a symlink")
        if not stat.S_ISREG(found.st_mode):
            raise ToolRefused("target is not a regular file")
        previous = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
        )
        try:
            stream = hashlib.sha256()
            while True:
                block = os.read(previous, _CHUNK)
                if not block:
                    break
                stream.update(block)
        finally:
            os.close(previous)
        return False, "sha256:" + stream.hexdigest()
