"""Hash-bound multi-file workspace replacements for the coding tool surface."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from tools import ToolContext, ToolResult

MAX_PATCH_FILES = 32
MAX_PATCH_FILE_BYTES = 256 * 1024


class _PatchConflictError(RuntimeError):
    """The target changed after batch validation but before its replacement."""


def _open_patch_parent(ctx: ToolContext, path: Path) -> tuple[int, str]:
    """Open a target's parent by directory fd, refusing symlinks at every step."""
    from tools import ToolAccessError, ToolInputError

    if ctx.sandbox is None:
        raise ToolAccessError("this tool context has no workspace sandbox")
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ToolAccessError("ApplyPatch requires directory-relative no-follow file operations")
    try:
        relative = path.relative_to(ctx.sandbox.root_real)
    except ValueError as error:
        raise ToolAccessError("patch target escapes the run workspace") from error
    parts = relative.parts
    if not parts:
        raise ToolInputError("patch target must be a file inside the workspace")
    directory_fd = os.open(
        ctx.sandbox.root_real,
        os.O_RDONLY | directory_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | directory_flag | nofollow_flag | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, parts[-1]
    except Exception:
        os.close(directory_fd)
        raise


def _read_patch_target(directory_fd: int, name: str) -> tuple[bytes, int]:
    """Read one bounded regular file without following its final component."""
    from tools import ToolInputError

    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PATCH_FILE_BYTES:
        raise ToolInputError(f"patch target must be a regular file no larger than {MAX_PATCH_FILE_BYTES} bytes")
    descriptor = os.open(
        name,
        os.O_RDONLY | nofollow_flag | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
        ):
            raise ToolInputError("patch target changed while it was being read")
        mode = stat.S_IMODE(opened.st_mode)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            raise ToolInputError("ApplyPatch refuses setuid or setgid files")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_PATCH_FILE_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PATCH_FILE_BYTES:
                raise ToolInputError(f"patch target exceeds the {MAX_PATCH_FILE_BYTES}-byte limit")
            chunks.append(chunk)
        return b"".join(chunks), mode
    finally:
        os.close(descriptor)


def _stage_patch_bytes(directory_fd: int, content: bytes, mode: int) -> str:
    """Create and fsync a same-directory replacement file, returning its name."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    name = ""
    descriptor = -1
    for _ in range(8):
        name = f".northstar-patch-{secrets.token_hex(12)}"
        try:
            descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
            break
        except FileExistsError:
            continue
    if descriptor < 0:
        raise OSError("could not allocate a unique patch staging file")
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while staging patch content")
            view = view[written:]
        os.fsync(descriptor)
        return name
    except Exception:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def _current_patch_matches(item: Mapping[str, Any]) -> bool:
    from tools import ToolInputError

    try:
        current, mode = _read_patch_target(item["directory_fd"], item["name"])
    except (OSError, ToolInputError):
        return False
    return (
        hashlib.sha256(current).hexdigest() == item["expected_sha256"]
        and mode == item["mode"]
    )


def apply_patch(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Apply bounded full-file replacements guarded by the hashes returned by Read."""
    from tools import ToolAccessError, ToolInputError, ToolResult

    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        return ToolResult.error("files must be a non-empty array")
    if len(raw_files) > MAX_PATCH_FILES:
        return ToolResult.error(f"ApplyPatch accepts at most {MAX_PATCH_FILES} files per call")

    prepared: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    total_new_bytes = 0
    try:
        for index, entry in enumerate(raw_files):
            if not isinstance(entry, dict):
                raise ToolInputError(f"files[{index}] must be an object")
            raw_path = entry.get("path")
            expected = entry.get("expected_sha256")
            content = entry.get("content")
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise ToolInputError(f"files[{index}].path must be a non-empty workspace-relative path")
            if Path(raw_path.strip()).is_absolute():
                raise ToolInputError(f"files[{index}].path must be workspace-relative")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                raise ToolInputError(f"files[{index}].expected_sha256 must be a 64-character SHA-256 hex digest from Read")
            if not isinstance(content, str):
                raise ToolInputError(f"files[{index}].content must be a UTF-8 string")
            if len(content) > MAX_PATCH_FILE_BYTES:
                raise ToolInputError(f"files[{index}].content exceeds the {MAX_PATCH_FILE_BYTES}-byte limit")
            if "\x00" in content:
                raise ToolInputError(f"files[{index}].content contains a NUL byte")
            try:
                new_bytes = content.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise ToolInputError(f"files[{index}].content is not valid UTF-8 text") from error
            if len(new_bytes) > MAX_PATCH_FILE_BYTES:
                raise ToolInputError(f"files[{index}].content exceeds the {MAX_PATCH_FILE_BYTES}-byte limit")
            total_new_bytes += len(new_bytes)
            if total_new_bytes > MAX_PATCH_FILE_BYTES * MAX_PATCH_FILES:
                raise ToolInputError("combined patch content exceeds the runtime limit")

            target = ctx.resolve(raw_path, for_write=True, must_exist=True)
            canonical = os.path.normcase(str(target))
            if canonical in seen_paths:
                raise ToolInputError(f"files[{index}] duplicates another patch target: {ctx.relative(target)}")
            seen_paths.add(canonical)
            directory_fd, name = _open_patch_parent(ctx, target)
            try:
                old_bytes, mode = _read_patch_target(directory_fd, name)
                actual = hashlib.sha256(old_bytes).hexdigest()
                if actual != expected.lower():
                    raise ToolInputError(
                        f"stale patch for {ctx.relative(target)}: expected {expected.lower()}, found {actual}; re-read before editing"
                    )
                try:
                    old_bytes.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    raise ToolInputError(f"patch target is not UTF-8 text: {ctx.relative(target)}") from error
                if b"\x00" in old_bytes:
                    raise ToolInputError(f"patch target is binary, not UTF-8 text: {ctx.relative(target)}")
                prepared.append(
                    {
                        "path": target,
                        "relative": ctx.relative(target),
                        "directory_fd": directory_fd,
                        "name": name,
                        "old_bytes": old_bytes,
                        "new_bytes": new_bytes,
                        "expected_sha256": expected.lower(),
                        "mode": mode,
                        "before_sha256": actual,
                        "after_sha256": hashlib.sha256(new_bytes).hexdigest(),
                        "staged_name": None,
                    }
                )
            except Exception:
                os.close(directory_fd)
                raise
    except (ToolInputError, ToolAccessError, OSError, ValueError) as error:
        for item in prepared:
            os.close(item["directory_fd"])
        return ToolResult.error(str(error))

    applied: list[dict[str, Any]] = []
    changed_items = [item for item in prepared if item["new_bytes"] != item["old_bytes"]]
    try:
        for item in changed_items:
            item["staged_name"] = _stage_patch_bytes(
                item["directory_fd"], item["new_bytes"], item["mode"]
            )
        # Check every precondition a second time before replacing the first file.
        # This catches concurrent edits during staging without leaving a partial patch.
        stale = [item["relative"] for item in prepared if not _current_patch_matches(item)]
        if stale:
            return ToolResult.error(
                "workspace changed while staging; no files were patched. Re-read: " + ", ".join(stale),
                files=stale,
            )
        for item in changed_items:
            if not _current_patch_matches(item):
                raise _PatchConflictError(
                    f"workspace changed before replacing {item['relative']}; re-read and rebuild the patch"
                )
            os.replace(
                item["staged_name"],
                item["name"],
                src_dir_fd=item["directory_fd"],
                dst_dir_fd=item["directory_fd"],
            )
            item["staged_name"] = None
            applied.append(item)
    except (OSError, _PatchConflictError) as error:
        rollback_errors: list[str] = []
        for item in reversed(applied):
            backup: str | None = None
            try:
                backup = _stage_patch_bytes(item["directory_fd"], item["old_bytes"], item["mode"])
                os.replace(
                    backup,
                    item["name"],
                    src_dir_fd=item["directory_fd"],
                    dst_dir_fd=item["directory_fd"],
                )
            except OSError as rollback_error:
                if backup:
                    try:
                        os.unlink(backup, dir_fd=item["directory_fd"])
                    except OSError:
                        pass
                rollback_errors.append(f"{item['relative']}: {rollback_error}")
        if rollback_errors:
            partial = [item["relative"] for item in applied]
            return ToolResult.error(
                f"patch commit failed: {error}; rollback also failed for " + ", ".join(rollback_errors),
                files_maybe_changed=partial,
            )
        return ToolResult.error(f"patch commit failed and prior replacements were rolled back: {error}")
    finally:
        for item in prepared:
            staged_name = item.get("staged_name")
            if staged_name:
                try:
                    os.unlink(staged_name, dir_fd=item["directory_fd"])
                except OSError:
                    pass
            os.close(item["directory_fd"])

    results = [
        {
            "path": item["relative"],
            "before_sha256": item["before_sha256"],
            "after_sha256": item["after_sha256"],
            "changed": item["new_bytes"] != item["old_bytes"],
        }
        for item in prepared
    ]
    summary = "\n".join(
        f"{item['path']}: {'changed' if item['changed'] else 'unchanged'} "
        f"{item['before_sha256']} -> {item['after_sha256']}"
        for item in results
    )
    return ToolResult(
        content=(
            f"validated {len(results)} file(s), replaced {len(changed_items)} after matching every expected SHA-256:\n{summary}"
        ),
        data={"files": results, "count": len(results), "changed_count": len(changed_items)},
    )
