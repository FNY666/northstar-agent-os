"""受限的本地扫描输入冻结；不执行候选项目代码，也不使用文件过滤器。"""
from __future__ import annotations

import ctypes
import errno
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from native_contract import EvidenceError, sha, wire


# These budgets cap both memory retained for normalizers and bytes copied to the scan view.
MAX_PATHS = 128
MAX_PATH_LENGTH = 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_REQUIREMENTS_BYTES = 1024 * 1024
MAX_REQUIREMENTS = 1024

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*\Z")
_NORMALIZED_NAME = re.compile(r"[-_.]+")
_REQUIREMENTS_FILE = re.compile(r"requirements(?:[-_][A-Za-z0-9._-]+)?\.txt\Z", re.IGNORECASE)
_CREDENTIAL_TOKEN = re.compile(
    r"(?:^|[-_.])(?:credential|credentials|secret|secrets|password|passwd|token|apikey|api[-_]?key)(?:$|[-_.])",
    re.IGNORECASE,
)
_PRIVATE_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys"})
_PRIVATE_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")


class _FreezeFailure(Exception):
    """Internal exception used to convert OS errors to the public contract error."""


def _raise(message: str, cause: BaseException | None = None) -> None:
    if cause is None:
        raise EvidenceError(message)
    raise EvidenceError(message) from cause


def _path_text(value: str | os.PathLike[str], *, label: str) -> str:
    if isinstance(value, bytes):
        _raise(f"{label} path must be text")
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        _raise(f"{label} path must be text", exc)
    if type(raw) is not str or not raw or "\x00" in raw:
        _raise(f"{label} path is invalid")
    return raw


def _components(raw: str, *, label: str, allow_absolute: bool) -> tuple[bool, list[str]]:
    absolute = raw.startswith(os.sep)
    if absolute and not allow_absolute:
        _raise(f"{label} must be a relative repository path")
    pieces = raw.split(os.sep)
    components: list[str] = []
    for piece in pieces:
        # Empty pieces only represent the leading slash or repeated separators in a host path.
        if piece == "":
            continue
        if piece in {".", ".."} or "\\" in piece:
            _raise(f"{label} contains an unsafe path component")
        components.append(piece)
    return absolute, components


def _open_directory(raw: str, *, label: str) -> int:
    """Open every host-path component through directory FDs without following links."""
    absolute, components = _components(raw, label=label, allow_absolute=True)
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


def _requested_components(path: str) -> list[str]:
    if type(path) is not str or not path or len(path) > MAX_PATH_LENGTH or "\x00" in path:
        _raise("requested input path is invalid")
    if path.startswith("/") or any(piece == "" for piece in path.split("/")):
        _raise("requested input path contains an empty or absolute component")
    _, components = _components(path, label="requested input path", allow_absolute=False)
    if not components:
        _raise("requested input path is empty")
    return components


def _reject_credential_path(components: list[str]) -> None:
    for component in components:
        lowered = component.lower()
        stem = lowered.rsplit(".", 1)[0] if "." in lowered else lowered
        if (
            lowered == ".env"
            or lowered.startswith(".env.")
            or lowered in _PRIVATE_KEY_NAMES
            or lowered.endswith(_PRIVATE_KEY_SUFFIXES)
            or _CREDENTIAL_TOKEN.search(stem)
        ):
            _raise("credential-bearing input paths are not allowed")


def _read_regular_at(root_fd: int, components: list[str]) -> bytes:
    """Read exactly one bounded, unlinked regular file using descriptor-relative traversal."""
    directory = os.dup(root_fd)
    file_fd: int | None = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for component in components[:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        file_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        file_fd = os.open(components[-1], file_flags, dir_fd=directory)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            _raise("scan inputs must be regular files")
        if before.st_nlink != 1:
            _raise("hard-linked scan inputs are not allowed")
        if before.st_size < 0 or before.st_size > MAX_FILE_BYTES:
            _raise("scan input exceeds the per-file byte budget")

        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                _raise("scan input changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        # A regular file that grows after the stat must not become an unbounded input.
        if os.read(file_fd, 1):
            _raise("scan input changed while being read")
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        fingerprint = (before.st_dev, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        after_fingerprint = (after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if fingerprint != after_fingerprint or len(raw) != before.st_size:
            _raise("scan input changed while being read")
        return raw
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("unable to write frozen input")
        view = view[written:]


def _mkdir_open_at(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        # A stage directory is private, so this is only a previously-created shared path.
        pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)


def _write_nested(stage_fd: int, components: list[str], raw: bytes) -> None:
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
        os.fchmod(file_fd, 0o400)
        os.fsync(file_fd)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory)


def _seal_directories(fd: int) -> None:
    """Make the freshly-created tree read-only before its atomic publication."""
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
            os.fchmod(child_fd, 0o500)
            os.fsync(child_fd)
        finally:
            os.close(child_fd)
    os.fchmod(fd, 0o500)
    os.fsync(fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    """Best-effort cleanup of a private staging tree after a failed publication."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError:
        return
    try:
        os.fchmod(fd, 0o700)
        for child in os.listdir(fd):
            try:
                child_stat = os.stat(child, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(child_stat.st_mode):
                    _remove_tree_at(fd, child)
                else:
                    os.unlink(child, dir_fd=fd)
            except OSError:
                # Cleanup cannot weaken the no-overwrite guarantee; retain no exception here.
                pass
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def _rename_noreplace(parent_fd: int, stage: str, target: str) -> None:
    lib = ctypes.CDLL(None, use_errno=True)
    rename = getattr(lib, "renameat2", None)
    if rename is None:
        _raise("platform lacks atomic no-overwrite renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # Linux RENAME_NOREPLACE. It refuses an existing file, directory, or symlink.
    if rename(parent_fd, stage.encode("ascii"), parent_fd, target.encode("utf-8"), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            _raise("frozen output already exists; refusing to overwrite it")
        raise OSError(code, "atomic no-overwrite publication failed")


def _publish_nested(output_dir: str | os.PathLike[str], files: dict[str, bytes]) -> str:
    raw_output = _path_text(output_dir, label="output")
    absolute, components = _components(raw_output, label="output", allow_absolute=True)
    if not components:
        _raise("output path must name a new directory")
    target = components[-1]
    if target in {".", ".."}:
        _raise("output path is invalid")

    parent_components = components[:-1]
    start = os.sep if absolute else "."
    parent_fd = os.open(start, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stage_fd: int | None = None
    stage: str | None = None
    published = False
    try:
        for component in parent_components:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        for _ in range(16):
            candidate = ".freeze-stage-" + secrets.token_hex(16)
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
                stage = candidate
                break
            except FileExistsError:
                continue
        if stage is None:
            _raise("unable to reserve private freeze staging directory")
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        for path in sorted(files):
            _write_nested(stage_fd, path.split("/"), files[path])
        _seal_directories(stage_fd)
        os.close(stage_fd)
        stage_fd = None
        _rename_noreplace(parent_fd, stage, target)
        published = True
        os.fsync(parent_fd)
        return os.path.abspath(raw_output)
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if stage is not None and not published:
            _remove_tree_at(parent_fd, stage)
        os.close(parent_fd)


def _is_requirements_file(path: str) -> bool:
    components = path.split("/")
    basename = components[-1]
    return bool(
        _REQUIREMENTS_FILE.fullmatch(basename)
        or ("requirements" in {component.lower() for component in components[:-1]} and basename.lower().endswith(".txt"))
    )


def validate_requirements(raw: bytes | str) -> list[dict[str, str]]:
    """Parse the deliberately small first-version requirements grammar.

    Only blank lines, full-line comments, and ``distribution==version`` pins are
    accepted. Extras, environment markers, URLs, options, include/constraint
    directives, hashes, editable installs, and version ranges are rejected.
    """
    if type(raw) is bytes:
        if len(raw) > MAX_REQUIREMENTS_BYTES:
            _raise("requirements input exceeds the byte budget")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            _raise("requirements input must be UTF-8", exc)
    elif type(raw) is str:
        try:
            raw_bytes = raw.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            _raise("requirements input must be UTF-8", exc)
        if len(raw_bytes) > MAX_REQUIREMENTS_BYTES:
            _raise("requirements input exceeds the byte budget")
        text = raw
    else:
        _raise("requirements input must be bytes or text")
    if "\x00" in text:
        _raise("requirements input contains NUL")

    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    lines = text.split("\n")
    if len(lines) > MAX_REQUIREMENTS + 1:
        _raise("requirements input has too many lines")
    for number, line in enumerate(lines, start=1):
        if line.endswith("\r"):
            line = line[:-1]
        if "\r" in line or any(ord(character) < 32 and character not in "\t" for character in line):
            _raise(f"requirements line {number} contains an unsupported control character")
        if not line or line.startswith("#"):
            continue
        # No surrounding whitespace or inline comments: both would enlarge the grammar.
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)", line)
        if match is None:
            _raise(f"requirements line {number} is not an exact ordinary package pin")
        name, version = match.groups()
        if not _NAME.fullmatch(name) or not _VERSION.fullmatch(version):
            _raise(f"requirements line {number} is not an exact ordinary package pin")
        normalized = _NORMALIZED_NAME.sub("-", name).lower()
        if normalized in seen:
            _raise(f"requirements line {number} repeats a package")
        seen.add(normalized)
        packages.append({"name": name, "version": version})
        if len(packages) > MAX_REQUIREMENTS:
            _raise("requirements input has too many packages")
    return packages


def freeze_inputs(source_dir: str | os.PathLike[str], output_dir: str | os.PathLike[str], paths: list[str]) -> dict[str, Any]:
    """Copy an explicit local input set into a new immutable-mode directory.

    The operation reads only caller-named relative files, through descriptor-relative
    ``O_NOFOLLOW`` traversal. It never executes project code and offers no include,
    exclude, glob, configuration, network, or command hooks. Publication is one
    directory rename using Linux ``RENAME_NOREPLACE``; an existing output is never
    replaced. The returned ``input_bytes`` are the same bytes hashed and copied.
    """
    if type(paths) is not list or not 1 <= len(paths) <= MAX_PATHS:
        _raise("input path list must contain between 1 and 128 paths")

    requested: dict[str, list[str]] = {}
    for path in paths:
        components = _requested_components(path)
        canonical = "/".join(components)
        if canonical in requested:
            _raise("input path list contains a duplicate")
        _reject_credential_path(components)
        requested[canonical] = components

    source_raw = _path_text(source_dir, label="source")
    source_fd: int | None = None
    try:
        source_fd = _open_directory(source_raw, label="source")
        copied: dict[str, bytes] = {}
        total = 0
        for path in sorted(requested):
            raw = _read_regular_at(source_fd, requested[path])
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                _raise("scan inputs exceed the total byte budget")
            if _is_requirements_file(path):
                validate_requirements(raw)
            copied[path] = raw
    except EvidenceError:
        raise
    except (OSError, ValueError) as exc:
        _raise("unable to securely read requested scan input", exc)
    finally:
        if source_fd is not None:
            os.close(source_fd)

    files = [{"path": path, "sha256": sha(copied[path]), "bytes": len(copied[path])} for path in sorted(copied)]
    manifest_sha256 = sha(wire({"files": files}))
    try:
        published_output = _publish_nested(output_dir, copied)
    except EvidenceError:
        raise
    except (OSError, ValueError) as exc:
        _raise("unable to atomically publish frozen inputs", exc)
    return {
        "files": files,
        "manifest_sha256": manifest_sha256,
        "output_dir": published_output,
        "input_bytes": dict(copied),
    }
