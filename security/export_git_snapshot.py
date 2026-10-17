"""Export a bounded, immutable candidate view from one explicitly named Git commit.

This module deliberately uses Git plumbing only to read content-addressed commit, tree,
and blob objects.  It never checks out, archives, filters, builds, installs, or runs
candidate code.  The published directory contains ``source/`` (the committed tree) and
``candidate-manifest.json`` (canonical metadata); it is atomically renamed only after
all object bytes have been checked and written to a private staging directory.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import selectors
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from trusted_common import EvidenceError, sha, wire


GIT = "/usr/bin/git"
MAX_FILES = 4096
MAX_PATH_BYTES = 1024
MAX_DEPTH = 64
MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_TREE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_TREE_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 8192
MAX_TREE_OBJECTS = 8192
MAX_COMMIT_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_PACK_ENTRIES = 4096
GIT_TIMEOUT_SECONDS = 20

_HEX_COMMIT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_VERSION = re.compile(rb"git version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\n?\Z")
_DECIMAL = re.compile(rb"[0-9]+\n\Z")

# This is a fresh environment, not a modification of the caller's environment.  The
# few values below are explicit Git safety controls, rather than inherited settings.
_CLEAN_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class _SnapshotFailure(Exception):
    """Internal failure, translated to the repository's public EvidenceError."""


def _fail(message: str, cause: BaseException | None = None) -> None:
    if cause is None:
        raise EvidenceError(message)
    raise EvidenceError(message) from cause


def _text_path(value: str | os.PathLike[str], label: str) -> str:
    if isinstance(value, bytes):
        _fail(f"{label} path must be text")
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        _fail(f"{label} path must be text", exc)
    if type(raw) is not str or not raw or "\x00" in raw:
        _fail(f"{label} path is invalid")
    return raw


def _host_components(raw: str, label: str) -> tuple[bool, list[str]]:
    absolute = raw.startswith(os.sep)
    pieces = raw.split(os.sep)
    components: list[str] = []
    for piece in pieces:
        if not piece:
            continue
        if piece in {".", ".."} or "\\" in piece:
            _fail(f"{label} contains an unsafe host path component")
        components.append(piece)
    return absolute, components


def _open_host_directory(raw: str, label: str) -> int:
    """Open a directory component by component without following any symlink."""
    absolute, components = _host_components(raw, label)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(os.sep if absolute else ".", flags)
    try:
        for component in components:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_dir_at(parent_fd: int, name: str, label: str) -> int:
    record = _lstat_at(parent_fd, name)
    if record is None or stat.S_ISLNK(record.st_mode) or not stat.S_ISDIR(record.st_mode):
        _fail(f"{label} must be a real directory, not a link")
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError as exc:
        _fail(f"unable to open {label}", exc)


def _read_regular_at(parent_fd: int, name: str, maximum: int, label: str, *, required: bool = False) -> bytes | None:
    record = _lstat_at(parent_fd, name)
    if record is None:
        if required:
            _fail(f"{label} is missing")
        return None
    if stat.S_ISLNK(record.st_mode) or not stat.S_ISREG(record.st_mode) or record.st_size < 0 or record.st_size > maximum:
        _fail(f"{label} must be a bounded regular file, not a link")
    fd: int | None = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != record.st_size:
            _fail(f"{label} changed while being read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                _fail(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            _fail(f"{label} exceeds its byte budget")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail(f"{label} changed while being read")
        return b"".join(chunks)
    except EvidenceError:
        raise
    except OSError as exc:
        _fail(f"unable to read {label}", exc)
    finally:
        if fd is not None:
            os.close(fd)


def _assert_regular_file_at(parent_fd: int, name: str, label: str) -> None:
    record = _lstat_at(parent_fd, name)
    if record is None or stat.S_ISLNK(record.st_mode) or not stat.S_ISREG(record.st_mode):
        _fail(f"{label} must be a regular file, not a link")


def _reject_dangerous_config(git_fd: int) -> None:
    raw = _read_regular_at(git_fd, "config", MAX_CONFIG_BYTES, "Git config")
    if raw is None:
        return
    # Git config is textual.  This conservative scan catches the three settings that
    # can redirect object reads/lazy object acquisition before any Git plumbing runs.
    text = raw.decode("latin-1").lower()
    for line in text.splitlines():
        uncommented = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not uncommented or uncommented.startswith("["):
            continue
        key = uncommented.split("=", 1)[0].strip().replace(" ", "")
        if key in {"partialclone", "promisor", "alternateobjectdirectories"}:
            _fail("partial, promisor, or alternate-object Git repositories are not supported")
        # A local include could introduce the above settings from a path outside this
        # repository.  Refuse it rather than asking Git to follow it.
        if key == "path" and "[include" in text:
            _fail("Git config includes are not supported for snapshot export")
    if re.search(r"(?m)^\s*\[\s*include(?:if)?\b", text):
        _fail("Git config includes are not supported for snapshot export")


def _reject_unsafe_object_store(git_fd: int) -> int:
    objects_fd = _open_dir_at(git_fd, "objects", "Git objects directory")
    info_fd: int | None = None
    pack_fd: int | None = None
    try:
        info_record = _lstat_at(objects_fd, "info")
        if info_record is not None:
            info_fd = _open_dir_at(objects_fd, "info", "Git objects/info directory")
            for name in ("alternates", "http-alternates"):
                if _lstat_at(info_fd, name) is not None:
                    _fail("alternate object stores are not supported")
        pack_record = _lstat_at(objects_fd, "pack")
        if pack_record is not None:
            pack_fd = _open_dir_at(objects_fd, "pack", "Git objects/pack directory")
            entries = list(os.scandir(pack_fd))
            if len(entries) > MAX_PACK_ENTRIES:
                _fail("Git pack directory exceeds the entry budget")
            for entry in entries:
                record = os.stat(entry.name, dir_fd=pack_fd, follow_symlinks=False)
                if stat.S_ISLNK(record.st_mode) or not stat.S_ISREG(record.st_mode):
                    _fail("Git pack directory contains an unsafe entry")
                if entry.name.endswith(".promisor"):
                    _fail("promisor Git repositories are not supported")
        return objects_fd
    except BaseException:
        os.close(objects_fd)
        raise
    finally:
        if info_fd is not None:
            os.close(info_fd)
        if pack_fd is not None:
            os.close(pack_fd)


def _open_repository(repository_path: str | os.PathLike[str]) -> tuple[str, int, int]:
    raw = _text_path(repository_path, "repository")
    root_fd = _open_host_directory(raw, "repository")
    git_fd: int | None = None
    objects_fd: int | None = None
    try:
        dotgit = _lstat_at(root_fd, ".git")
        if dotgit is not None:
            if stat.S_ISLNK(dotgit.st_mode):
                _fail("repository .git must not be a symlink")
            if not stat.S_ISDIR(dotgit.st_mode):
                _fail("gitfiles and linked worktrees are not supported")
            git_fd = _open_dir_at(root_fd, ".git", "repository .git")
            git_dir = os.path.join(os.path.abspath(raw), ".git")
        else:
            # A bare repository has HEAD and objects at the caller-specified root.
            git_fd = os.dup(root_fd)
            git_dir = os.path.abspath(raw)
        if _lstat_at(git_fd, "commondir") is not None:
            _fail("linked worktree Git directories are not supported")
        _assert_regular_file_at(git_fd, "HEAD", "Git HEAD")
        _reject_dangerous_config(git_fd)
        objects_fd = _reject_unsafe_object_store(git_fd)
        return git_dir, git_fd, objects_fd
    except BaseException:
        if objects_fd is not None:
            os.close(objects_fd)
        if git_fd is not None:
            os.close(git_fd)
        raise
    finally:
        os.close(root_fd)


def _ensure_git_supports_no_lazy_fetch() -> None:
    """Fail closed on a Git too old for the direct no-lazy-fetch safety control."""
    try:
        completed = subprocess.run(
            [GIT, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.sep,
            env=dict(_CLEAN_GIT_ENV),
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _fail("trusted Git executable is unavailable", exc)
    match = _VERSION.fullmatch(completed.stdout)
    if completed.returncode != 0 or match is None:
        _fail("trusted Git version check failed")
    # GIT_NO_LAZY_FETCH is present in the maintained Git releases newer than 2.20.
    if (int(match.group(1)), int(match.group(2))) < (2, 20):
        _fail("installed Git lacks the required no-lazy-fetch control")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        pass


def _run_git(git_dir: str, arguments: list[str], stdout_limit: int) -> bytes:
    """Run fixed Git plumbing argv with bounded stdout and stderr, never a shell."""
    if not arguments or any(type(item) is not str for item in arguments):
        _fail("internal Git argv is invalid")
    argv = [
        GIT,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.useReplaceRefs=false",
        "--no-replace-objects",
        f"--git-dir={git_dir}",
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.sep,
            env=dict(_CLEAN_GIT_ENV),
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        _fail("unable to start trusted Git", exc)

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_limit))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", MAX_GIT_STDERR_BYTES))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    exceeded = False
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(process)
                break
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                stream, limit = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[stream].extend(chunk)
                if len(buffers[stream]) > limit:
                    exceeded = True
                    _kill_process_group(process)
                    break
            if exceeded:
                break
    finally:
        selector.close()
    if exceeded or timed_out:
        _kill_process_group(process)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        process.wait(timeout=2)
    if timed_out:
        _fail("Git object query exceeded the time budget")
    if exceeded:
        _fail("Git object query exceeded the stdout or stderr budget")
    if process.returncode != 0:
        _fail("Git object query failed")
    return bytes(buffers["stdout"])


def _check_loose_object_location(objects_fd: int, oid: str) -> None:
    """Do not let Git follow a symlink for a loose object used by this export."""
    prefix, suffix = oid[:2], oid[2:]
    record = _lstat_at(objects_fd, prefix)
    if record is None:
        return
    if stat.S_ISLNK(record.st_mode) or not stat.S_ISDIR(record.st_mode):
        _fail("Git object directory contains an unsafe loose-object entry")
    directory = _open_dir_at(objects_fd, prefix, "Git loose-object directory")
    try:
        object_record = _lstat_at(directory, suffix)
        if object_record is not None and (stat.S_ISLNK(object_record.st_mode) or not stat.S_ISREG(object_record.st_mode)):
            _fail("Git loose object is not a regular file")
    finally:
        os.close(directory)


def _git_object_id(kind: str, raw: bytes, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    digest.update(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0")
    digest.update(raw)
    return digest.hexdigest()


def _get_object(git_dir: str, objects_fd: int, oid: str, kind: str, maximum: int, algorithm: str) -> bytes:
    _check_loose_object_location(objects_fd, oid)
    actual_kind = _run_git(git_dir, ["cat-file", "-t", oid], 128)
    if actual_kind != kind.encode("ascii") + b"\n":
        _fail("Git object has an unexpected type")
    size_raw = _run_git(git_dir, ["cat-file", "-s", oid], 128)
    if _DECIMAL.fullmatch(size_raw) is None:
        _fail("Git object size response is invalid")
    size = int(size_raw[:-1])
    if size > maximum:
        _fail("Git object exceeds the configured byte budget")
    raw = _run_git(git_dir, ["cat-file", kind, oid], maximum)
    if len(raw) != size:
        _fail("Git object changed while being read")
    if _git_object_id(kind, raw, algorithm) != oid:
        _fail("Git object bytes do not match their content-addressed object ID")
    return raw


def _commit_tree(raw: bytes, oid_length: int) -> str:
    headers = raw.split(b"\n\n", 1)[0].split(b"\n")
    tree_values = [line[5:] for line in headers if line.startswith(b"tree ")]
    if len(tree_values) != 1 or len(tree_values[0]) != oid_length:
        _fail("commit object does not contain one valid tree ID")
    try:
        tree = tree_values[0].decode("ascii")
    except UnicodeDecodeError as exc:
        _fail("commit tree ID is not ASCII", exc)
    if not re.fullmatch(r"[0-9a-f]+", tree):
        _fail("commit tree ID is invalid")
    return tree


def _tree_entries(raw: bytes, oid_bytes: int) -> list[tuple[str, bytes, str]]:
    entries: list[tuple[str, bytes, str]] = []
    offset = 0
    while offset < len(raw):
        space = raw.find(b" ", offset)
        if space <= offset:
            _fail("Git tree entry mode is malformed")
        nul = raw.find(b"\0", space + 1)
        if nul < 0 or nul == space + 1:
            _fail("Git tree entry name is malformed")
        next_offset = nul + 1 + oid_bytes
        if next_offset > len(raw):
            _fail("Git tree entry object ID is truncated")
        try:
            mode = raw[offset:space].decode("ascii")
        except UnicodeDecodeError as exc:
            _fail("Git tree entry mode is not ASCII", exc)
        entries.append((mode, raw[space + 1:nul], raw[nul + 1:next_offset].hex()))
        if len(entries) > MAX_TREE_ENTRIES:
            _fail("Git tree exceeds the entry-count budget")
        offset = next_offset
    return entries


def _safe_tree_name(raw: bytes) -> str:
    if not raw or b"/" in raw or b"\\" in raw or raw in {b".", b".."}:
        _fail("Git tree contains an unsafe path component")
    try:
        name = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        _fail("Git tree pathname is not UTF-8", exc)
    if "\x00" in name or len(raw) > MAX_PATH_BYTES:
        _fail("Git tree pathname exceeds the safety budget")
    return name


def _enumerate_blobs(git_dir: str, objects_fd: int, root_tree: str, algorithm: str) -> list[dict[str, Any]]:
    oid_bytes = 20 if algorithm == "sha1" else 32
    records: list[dict[str, Any]] = []
    claimed: dict[str, str] = {}
    tree_bytes = 0
    tree_objects = 0

    def walk(tree: str, prefix: tuple[str, ...], depth: int) -> None:
        nonlocal tree_bytes, tree_objects
        if depth > MAX_DEPTH:
            _fail("Git tree nesting exceeds the depth budget")
        raw = _get_object(git_dir, objects_fd, tree, "tree", MAX_TREE_BYTES, algorithm)
        tree_objects += 1
        tree_bytes += len(raw)
        if tree_objects > MAX_TREE_OBJECTS or tree_bytes > MAX_TOTAL_TREE_BYTES:
            _fail("Git tree traversal exceeds the aggregate budget")
        for mode, raw_name, child_oid in _tree_entries(raw, oid_bytes):
            name = _safe_tree_name(raw_name)
            path_parts = prefix + (name,)
            path = "/".join(path_parts)
            if len(path.encode("utf-8")) > MAX_PATH_BYTES:
                _fail("Git tree pathname exceeds the safety budget")
            old_kind = claimed.get(path)
            if old_kind is not None:
                _fail("Git tree has duplicate or file/directory-conflicting paths")
            if mode == "40000":
                claimed[path] = "directory"
                walk(child_oid, path_parts, depth + 1)
                continue
            if mode not in {"100644", "100755"}:
                _fail("Git tree contains symlink, submodule, or unsupported special entry")
            claimed[path] = "file"
            records.append({"path": path, "git_blob": child_oid, "mode": mode})
            if len(records) > MAX_FILES:
                _fail("Git tree exceeds the file-count budget")

    walk(root_tree, (), 0)
    # This also yields a deterministic manifest and avoids staging namespace surprises.
    records.sort(key=lambda item: item["path"])
    return records


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short write to snapshot staging file")
        view = view[count:]


def _mkdir_open_at(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)


def _write_nested(stage_fd: int, components: list[str], raw: bytes, mode: int) -> None:
    directory = os.dup(stage_fd)
    file_fd: int | None = None
    try:
        for component in components[:-1]:
            child = _mkdir_open_at(directory, component)
            os.close(directory)
            directory = child
        file_fd = os.open(
            components[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        _write_all(file_fd, raw)
        os.fchmod(file_fd, mode)
        os.fsync(file_fd)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)


def _seal_directories(fd: int) -> None:
    for name in os.listdir(fd):
        child_fd: int | None = None
        try:
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except OSError as exc:
            if exc.errno in {errno.ENOTDIR, errno.ELOOP}:
                continue
            raise
        try:
            _seal_directories(child_fd)
            os.fchmod(child_fd, 0o555)
            os.fsync(child_fd)
        finally:
            os.close(child_fd)
    os.fchmod(fd, 0o555)
    os.fsync(fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError:
        return
    try:
        os.fchmod(fd, 0o700)
        for child in os.listdir(fd):
            try:
                record = os.stat(child, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(record.st_mode):
                    _remove_tree_at(fd, child)
                else:
                    os.unlink(child, dir_fd=fd)
            except OSError:
                pass
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def _rename_noreplace(parent_fd: int, stage: str, target: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None:
        _fail("platform lacks atomic no-overwrite renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, stage.encode("ascii"), parent_fd, target.encode("utf-8"), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            _fail("snapshot output already exists; refusing to overwrite it")
        raise OSError(code, "atomic no-overwrite snapshot publication failed")


class _PrivateStage:
    """A private output staging directory, published exactly once with renameat2."""

    def __init__(self, output_dir: str | os.PathLike[str]) -> None:
        raw = _text_path(output_dir, "output")
        absolute, components = _host_components(raw, "output")
        if not components:
            _fail("output path must name a new directory")
        self.target = components[-1]
        self.parent_fd = os.open(os.sep if absolute else ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.stage_fd: int | None = None
        self.stage: str | None = None
        self.published = False
        try:
            for component in components[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
                os.close(self.parent_fd)
                self.parent_fd = child
            for _ in range(16):
                candidate = ".git-snapshot-stage-" + secrets.token_hex(16)
                try:
                    os.mkdir(candidate, 0o700, dir_fd=self.parent_fd)
                    self.stage = candidate
                    break
                except FileExistsError:
                    continue
            if self.stage is None:
                _fail("unable to reserve private snapshot staging directory")
            self.stage_fd = os.open(self.stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
        except BaseException:
            self.close()
            raise

    def write_source(self, path: str, raw: bytes, mode: str) -> None:
        if self.stage_fd is None:
            _fail("snapshot staging is not available")
        physical_mode = 0o555 if mode == "100755" else 0o444
        _write_nested(self.stage_fd, ["source", *path.split("/")], raw, physical_mode)

    def write_manifest(self, raw: bytes) -> None:
        if self.stage_fd is None:
            _fail("snapshot staging is not available")
        _write_nested(self.stage_fd, ["candidate-manifest.json"], raw, 0o444)

    def publish(self) -> None:
        if self.stage_fd is None or self.stage is None:
            _fail("snapshot staging is not available")
        _seal_directories(self.stage_fd)
        os.close(self.stage_fd)
        self.stage_fd = None
        _rename_noreplace(self.parent_fd, self.stage, self.target)
        self.published = True
        os.fsync(self.parent_fd)

    def close(self) -> None:
        if self.stage_fd is not None:
            os.close(self.stage_fd)
            self.stage_fd = None
        if self.stage is not None and not self.published:
            _remove_tree_at(self.parent_fd, self.stage)
        if getattr(self, "parent_fd", None) is not None:
            os.close(self.parent_fd)
            self.parent_fd = None  # type: ignore[assignment]


def export_git_snapshot(repository_path: str | os.PathLike[str], commit: str, output_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Export exactly one full Git commit tree into a new immutable directory.

    ``commit`` must be a caller-supplied full 40- or 64-hex object ID; refs, tags,
    abbreviated IDs, revisions, and paths are rejected.  Only regular Git tree blobs
    (mode ``100644`` or ``100755``) are supported.  The return value contains the
    canonical Git commit/tree IDs, per-file Git blob IDs and SHA-256s, manifest SHA-256,
    byte totals, and the published directory.  It intentionally does not return all
    candidate bytes in memory.

    Content-addressed IDs detect object-byte mismatch while objects are read.  They do
    not claim to defend against a malicious local host, kernel, or post-publication
    privileged writer; callers need their own trusted CI filesystem boundary.
    """
    if type(commit) is not str or _HEX_COMMIT.fullmatch(commit) is None:
        _fail("commit must be an explicitly supplied full 40- or 64-hex object ID")
    requested_commit = commit.lower()
    git_fd: int | None = None
    objects_fd: int | None = None
    stage: _PrivateStage | None = None
    try:
        _ensure_git_supports_no_lazy_fetch()
        git_dir, git_fd, objects_fd = _open_repository(repository_path)
        algorithm = "sha1" if len(requested_commit) == 40 else "sha256"
        raw_commit = _get_object(git_dir, objects_fd, requested_commit, "commit", MAX_COMMIT_BYTES, algorithm)
        tree = _commit_tree(raw_commit, len(requested_commit))
        records = _enumerate_blobs(git_dir, objects_fd, tree, algorithm)

        stage = _PrivateStage(output_dir)
        total = 0
        for record in records:
            raw_blob = _get_object(git_dir, objects_fd, record["git_blob"], "blob", MAX_BLOB_BYTES, algorithm)
            total += len(raw_blob)
            if total > MAX_TOTAL_BYTES:
                _fail("Git snapshot exceeds the total byte budget")
            record["sha256"] = sha(raw_blob)
            record["bytes"] = len(raw_blob)
            stage.write_source(record["path"], raw_blob, record["mode"])

        manifest = {
            "schema": "northstar.git-snapshot.v1",
            "git": {"commit": requested_commit, "tree": tree, "object_format": algorithm},
            "files": records,
            "file_count": len(records),
            "total_bytes": total,
        }
        manifest_raw = wire(manifest)
        manifest_sha256 = sha(manifest_raw)
        stage.write_manifest(manifest_raw)
        stage.publish()
        published = os.path.abspath(_text_path(output_dir, "output"))
        return {
            "git_commit": requested_commit,
            "git_tree": tree,
            "files": records,
            "file_count": len(records),
            "total_bytes": total,
            "candidate_manifest_sha256": manifest_sha256,
            "manifest_sha256": manifest_sha256,
            "output_dir": published,
        }
    except EvidenceError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        _fail("unable to securely export committed Git snapshot", exc)
    finally:
        if stage is not None:
            stage.close()
        if objects_fd is not None:
            os.close(objects_fd)
        if git_fd is not None:
            os.close(git_fd)
