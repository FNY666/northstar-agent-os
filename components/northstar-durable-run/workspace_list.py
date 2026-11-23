"""Bounded metadata-only workspace listings; not an OS sandbox.

The tool owns a host-resolved root and walks every requested directory through
file descriptors opened with ``O_NOFOLLOW``. It returns names, kinds, and file
sizes only: a listing must never become a shortcut around ``repo.read`` for
file content. Symlinks are neither followed nor returned.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from action_gateway import ToolExecutionFailed, ToolRefused

_MAX_PATH = 1024
_MAX_DEPTH = 8
_MAX_ENTRIES = 512


def _parts(prefix: object, *, allow_root: bool = True) -> tuple[str, ...]:
    if prefix == "" and allow_root:
        return ()
    if not isinstance(prefix, str) or not prefix or len(prefix) > _MAX_PATH:
        raise ToolRefused("invalid listing prefix")
    parts = tuple(prefix.split("/"))
    if any(part in {"", ".", ".."} or "\\" in part or "\x00" in part for part in parts):
        raise ToolRefused("invalid listing prefix")
    return parts


def _bounded_int(value: object, *, field: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ToolRefused(f"invalid {field}")
    return value


@dataclass(frozen=True)
class WorkspaceListResult:
    prefix: str
    entries: tuple[dict[str, Any], ...]
    truncated: bool

    def as_output(self) -> dict[str, Any]:
        return {
            "prefix": self.prefix,
            "entries": [dict(entry) for entry in self.entries],
            "truncated": self.truncated,
        }


class WorkspaceListTool:
    """List a bounded, symlink-free part of one host-owned workspace root."""

    def __init__(self, root, *, allowed_prefixes=None):
        self.root = Path(os.path.realpath(root))
        if not self.root.is_dir():
            raise ValueError("workspace root must be an existing directory")
        self.allowed_prefixes = None if allowed_prefixes is None else frozenset(allowed_prefixes)
        if self.allowed_prefixes is not None:
            for prefix in self.allowed_prefixes:
                _parts(prefix)

    def __call__(self, payload: object) -> WorkspaceListResult:
        if not isinstance(payload, dict) or set(payload) != {"prefix", "max_depth", "max_entries"}:
            raise ToolRefused("invalid list payload")
        prefix = payload["prefix"]
        prefix_parts = _parts(prefix)
        max_depth = _bounded_int(payload["max_depth"], field="listing depth", maximum=_MAX_DEPTH)
        max_entries = _bounded_int(payload["max_entries"], field="listing entry bound", maximum=_MAX_ENTRIES)
        if not self._authorized(prefix):
            raise ToolRefused("listing prefix is not authorized")

        directory_fd = None
        try:
            directory_fd = self._open_root()
            for part in prefix_parts:
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except FileNotFoundError:
                    raise ToolExecutionFailed("listing prefix is unavailable") from None
                except NotADirectoryError:
                    raise ToolRefused("listing prefix is not a directory") from None
                except OSError:
                    raise ToolRefused("listing prefix is not safely accessible") from None
                os.close(directory_fd)
                directory_fd = child
            entries: list[dict[str, Any]] = []
            truncated = self._walk(
                directory_fd,
                prefix,
                depth=1,
                max_depth=max_depth,
                max_entries=max_entries,
                entries=entries,
            )
            return WorkspaceListResult(prefix, tuple(entries), truncated)
        except ToolRefused:
            raise
        except ToolExecutionFailed:
            raise
        except OSError:
            raise ToolExecutionFailed("workspace listing failed") from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def _authorized(self, prefix: str) -> bool:
        if self.allowed_prefixes is None:
            return True
        return any(
            allowed == "" or prefix == allowed or prefix.startswith(allowed + "/")
            for allowed in self.allowed_prefixes
        )

    def _open_root(self) -> int:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except OSError:
            os.close(fd)
            raise

    def _walk(
        self,
        directory_fd: int,
        prefix: str,
        *,
        depth: int,
        max_depth: int,
        max_entries: int,
        entries: list[dict[str, Any]],
    ) -> bool:
        """Return true only when another eligible entry exceeds the bound."""
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError:
            raise ToolExecutionFailed("workspace listing is unavailable") from None
        for name in names:
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                # A concurrent deletion is not an escaped path; omit it.
                continue
            except OSError:
                raise ToolExecutionFailed("workspace listing changed during scan") from None
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                kind, size = "directory", None
            elif stat.S_ISREG(metadata.st_mode):
                kind, size = "file", metadata.st_size
            else:
                continue
            path = name if not prefix else f"{prefix}/{name}"
            if len(entries) >= max_entries:
                return True
            entries.append({"path": path, "kind": kind, "size_bytes": size})
            if kind == "directory" and depth < max_depth:
                try:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                except FileNotFoundError:
                    continue
                except OSError:
                    raise ToolExecutionFailed("workspace directory is unavailable") from None
                try:
                    if self._walk(
                        child,
                        path,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_entries=max_entries,
                        entries=entries,
                    ):
                        return True
                finally:
                    os.close(child)
        return False
