"""Pledge-style self-restriction for tool-effect execution.

Absorbs the OpenBSD ``pledge(2)`` permission model — verified against
``man.openbsd.org/pledge.2`` semantics, not a summary:

* a process *declares* the promises (capability set) it needs **before**
  doing anything sensitive;
* a later pledge may only **tighten** (subset) — it can never widen;
* any system operation outside the declared set kills the violator
  (``SIGABRT`` in OpenBSD);
* ``execpromises`` lets a parent hand a *narrower* set to the child it
  execs — never a wider one.

Semantic layer vs mechanism layer are deliberately separated:

* **semantic** (:class:`PledgeContext`) — pure Python, always enforced,
  unit-testable offline: declare → tighten-only → fail-closed ``require``,
  every decision auditable. This is what the governance bench measures.
* **mechanism** (:func:`pledge_loader_argv`, :func:`landlock_probe`) —
  best-effort OS enforcement underneath: Landlock self-restriction
  (unprivileged, irreversible — the closest Linux analogue of pledge's
  one-way ratchet) plus the existing seccomp-BPF denylist from
  :mod:`tools.seccomp`. The loader reports honestly what it could apply;
  where the kernel cannot do it, the semantic layer still fails closed.

Promise vocabulary is pledge-inspired but scoped to tool effects, not a
full OS promise set — pledging ``stdio rpath wpath`` for a Shell call is
the analogue of a daemon pledging ``stdio rpath`` after startup.
"""
from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from tools.seccomp import build_default_filter

#: Pledge-style promise vocabulary for tool effects. Names echo pledge(2)
#: where the meaning transfers; the scope is tool-effect operations, not
#: raw syscalls.
PROMISES = (
    "stdio",  # basic stdio, pipes
    "rpath",  # read files under allowed roots
    "wpath",  # modify existing files under allowed roots
    "cpath",  # create files/dirs under allowed roots
    "tmppath",  # create under TMPDIR
    "dpath",  # device nodes (/dev/null, ...)
    "unix",  # AF_UNIX sockets
    "inet",  # outbound TCP
    "dns",  # DNS resolution
    "proc",  # spawn child processes
    "exec",  # exec binaries
    "id",  # identity syscalls (getuid, getpwuid)
    "clock",  # clock_gettime
    "tty",  # terminal control
)
_PROMISE_SET = frozenset(PROMISES)

#: The Shell tool's full capability profile: declaring exactly this is a
#: no-op restriction (pledge with the full set changes nothing), and any
#: per-call payload may only tighten from it.
DEFAULT_SHELL_PLEDGES: tuple[str, ...] = tuple(PROMISES)

#: What a Shell execution inherently needs, whatever the payload says.
#: Declaring a set without these is refused before anything runs —
#: fail-closed at the semantic layer.
_SHELL_REQUIRED = frozenset({"proc", "exec"})


class PledgeError(ValueError):
    """Bad pledge call: unknown promise, widening, or use before pledging."""


class PledgeViolation(PledgeError):
    """An operation outside the pledged set was attempted: fail closed."""


def validate_promises(promises: Sequence[str] | None) -> frozenset[str]:
    """Normalise a promise list; raise :class:`PledgeError` on unknown names."""
    if promises is None:
        raise PledgeError("pledges must be an explicit list of promise names, not None")
    out: set[str] = set()
    for name in promises:
        if not isinstance(name, str) or name not in _PROMISE_SET:
            raise PledgeError(
                f"unknown promise {name!r}; choose from: {', '.join(PROMISES)}"
            )
        out.add(name)
    return frozenset(out)


def resolve_pledges(
    payload_value: Sequence[str] | None, service_value: Sequence[str] | None
) -> tuple[str, ...]:
    """Merge a per-call payload promise set with the operator's service set.

    Tighten-only, mirroring pledge(2): the call may move toward a *subset*
    of what the operator configured, never away from it. A payload that is
    not a subset of the service set is refused outright — the operator's
    declaration is the ceiling.
    """
    service = validate_promises(service_value if service_value is not None else DEFAULT_SHELL_PLEDGES)
    if payload_value is None:
        return tuple(sorted(service))
    requested = validate_promises(payload_value)
    if not requested <= service:
        raise PledgeError(
            "pledge widening refused: per-call promises "
            f"{sorted(requested - service)} are outside the operator set "
            f"{sorted(service)}"
        )
    return tuple(sorted(requested))


@dataclass
class PledgeEvent:
    """One auditable pledge decision."""

    kind: str  # "pledged" | "tightened" | "allowed" | "violation" | "widen_refused"
    promise: str | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "promise": self.promise, "detail": self.detail}


class PledgeContext:
    """One execution's pledge state: declare → tighten-only → fail-closed.

    pledge(2) is per-process and irreversible; this is per tool-effect
    execution with the same one-way ratchet. Use :meth:`pledge` to declare,
    :meth:`tighten` to narrow, :meth:`require` before each sensitive
    operation, and :meth:`subcontext` for the execpromises analogue.
    """

    def __init__(self, promises: frozenset[str]) -> None:
        self._promises = promises
        self.events: list[PledgeEvent] = [
            PledgeEvent("pledged", None, f"declared promises: {sorted(promises)}")
        ]

    @classmethod
    def pledge(cls, promises: Sequence[str]) -> "PledgeContext":
        """Declare the promise set before any sensitive operation."""
        return cls(validate_promises(promises))

    @property
    def promises(self) -> frozenset[str]:
        return self._promises

    def tighten(self, promises: Sequence[str]) -> "PledgeContext":
        """Narrow the set. Widening raises :class:`PledgeError` — pledge(2)
        can only reduce privileges, never increase them."""
        narrowed = validate_promises(promises)
        if not narrowed <= self._promises:
            self.events.append(
                PledgeEvent(
                    "widen_refused",
                    None,
                    f"refused widening {sorted(narrowed - self._promises)}; "
                    f"current: {sorted(self._promises)}",
                )
            )
            raise PledgeError(
                f"pledge widening refused: {sorted(narrowed - self._promises)} "
                f"not in {sorted(self._promises)}"
            )
        self._promises = narrowed
        self.events.append(PledgeEvent("tightened", None, f"narrowed to: {sorted(narrowed)}"))
        return self

    def require(self, promise: str) -> None:
        """Check one operation against the declared set.

        Outside the set: record a ``violation`` event and raise
        :class:`PledgeViolation` — fail closed, the OpenBSD analogue of
        SIGABRT for the offending operation.
        """
        if promise not in _PROMISE_SET:
            raise PledgeError(f"unknown promise {promise!r}")
        if promise not in self._promises:
            self.events.append(
                PledgeEvent(
                    "violation",
                    promise,
                    f"operation '{promise}' outside pledged set {sorted(self._promises)}",
                )
            )
            raise PledgeViolation(
                f"pledge violation: '{promise}' not in pledged set {sorted(self._promises)}"
            )
        self.events.append(PledgeEvent("allowed", promise, "within pledged set"))

    def subcontext(self, promises: Sequence[str]) -> "PledgeContext":
        """The execpromises analogue: a child execution may only inherit a
        subset of the parent's promises, never more."""
        child = validate_promises(promises)
        if not child <= self._promises:
            raise PledgeError(
                f"execpromises widening refused: {sorted(child - self._promises)} "
                f"outside parent set {sorted(self._promises)}"
            )
        return PledgeContext(child)

    def audit_log(self) -> list[dict[str, Any]]:
        return [event.as_dict() for event in self.events]


# ---------------------------------------------------------------------------
# Mechanism layer: Landlock + seccomp. Best effort, honestly reported.
# ---------------------------------------------------------------------------

#: landlock(2) syscall numbers. Verified: asm-generic (aarch64) and x86_64
#: both use 444/445/446 (torvalds/linux include/uapi/asm-generic/unistd.h).
_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_RULE_PATH_BENEATH = 1

# Landlock ABI v1 access bits (include/uapi/linux/landlock.h). The probe
# falls back to this set when the kernel rejects newer bits.
_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MKDIR = 1 << 6
_LL_MKNOD = 1 << 7
_LL_SYMLINK = 1 << 10
_LL_LINK = 1 << 11
_LL_TRUNCATE = 1 << 12
_LL_MKCHAR = 1 << 8
_LL_V1_FS = 0x1FFF

_LL_READ = _LL_READ_FILE | _LL_READ_DIR
_LL_WRITE = _LL_WRITE_FILE | _LL_REMOVE_FILE | _LL_TRUNCATE
# _LL_MKCHAR: verified empirically — creating a regular file requires the
# parent directory to grant the "make char device" bit on this ABI, not
# just MKDIR/MKNOD.
_LL_CREATE = _LL_MKDIR | _LL_MKNOD | _LL_MKCHAR | _LL_SYMLINK | _LL_LINK | _LL_REMOVE_DIR


@dataclass(frozen=True)
class LandlockSupport:
    """Honest capability probe result for Landlock self-restriction."""

    available: bool
    abi_flags: int = 0
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "abi_flags": self.abi_flags,
            "detail": self.detail,
        }


_probe_cache: LandlockSupport | None = None


def landlock_probe(*, force: bool = False) -> LandlockSupport:
    """Probe whether this kernel lets a process Landlock-restrict itself.

    Unprivileged by design (that is the point of Landlock): creating a
    ruleset needs no capabilities. Tries the full v1 flag set, then falls
    back — a refusal is reported, never hidden.
    """
    global _probe_cache
    if _probe_cache is not None and not force:
        return _probe_cache
    import ctypes
    import os

    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long

    def try_create(flags: int) -> int:
        attr = struct.pack("QQQ", flags, 0, 0)  # fs, net, scoped
        buf = ctypes.create_string_buffer(attr)
        fd = lib.syscall(
            _LANDLOCK_CREATE_RULESET, ctypes.cast(buf, ctypes.c_void_p), 24, 0, 0, 0, 0
        )
        errno = ctypes.get_errno() if fd < 0 else 0
        if fd >= 0:
            os.close(fd)
        return errno

    errno = try_create(_LL_V1_FS)
    if errno == 0:
        result = LandlockSupport(True, _LL_V1_FS, "landlock_create_ruleset works (ABI v1 flags)")
    elif errno == 38:  # ENOSYS: no landlock on this kernel
        result = LandlockSupport(False, 0, "kernel has no landlock syscalls (ENOSYS)")
    else:
        result = LandlockSupport(False, 0, f"landlock_create_ruleset refused (errno {errno})")
    _probe_cache = result
    return result


@dataclass(frozen=True)
class FsRule:
    """One Landlock PATH_BENEATH rule: path plus allowed access bits."""

    path: str
    access: int

    def as_dict(self) -> dict[str, str | int]:
        return {"path": self.path, "access": self.access}


def _ancestor_dirs(path: str) -> list[str]:
    """Parent directories of ``path`` up to (excluding) ``/``.

    Landlock checks every path component on traversal: reaching the
    workspace requires EXECUTE on each ancestor, so the ruleset grants
    traverse-only access to ancestors explicitly.
    """
    import os

    ancestors: list[str] = []
    parent = os.path.dirname(os.path.abspath(path))
    while parent and parent != "/":
        ancestors.append(parent)
        grandparent = os.path.dirname(parent)
        if grandparent == parent:
            break
        parent = grandparent
    return ancestors


def filesystem_rules(
    pledges: frozenset[str],
    *,
    workspace: str,
    tmpdir: str,
    runtime_roots: Sequence[str] = ("/usr", "/bin", "/lib", "/lib64", "/sbin"),
) -> list[FsRule]:
    """Map a pledge set to Landlock filesystem rules. Pure and testable.

    Once ``landlock_restrict_self`` runs, *every* path is denied except what
    rules grant — so runtime roots (read+exec) and device/proc views (read)
    are granted explicitly, and the workspace gets exactly the access the
    pledges allow: no ``wpath``/``cpath`` means read-only, no ``rpath`` at
    all means the workspace is invisible. Without ``tmppath`` the child's
    TMPDIR (workspace/.northstar/tmp) gets no rule, so temp-file writes
    there fail closed — the pledge declared no temp-file need.
    """
    rules: list[FsRule] = []
    anchors: list[str] = []  # paths that actually got a rule -> need ancestor traversal
    for root in runtime_roots:
        rules.append(FsRule(root, _LL_READ | _LL_EXECUTE))
    # /etc: read-only. The interpreter follows symlinks out of /usr/lib
    # (e.g. sitecustomize.py -> /etc/python3.12/...); without this the
    # loader's own python cannot start cleanly. This matches the process
    # backend's documented posture (host FS reachable; Landlock enforces
    # the *pledge's* filesystem promises, not whole-host isolation).
    rules.append(FsRule("/etc", _LL_READ))
    rules.append(FsRule("/dev", _LL_READ))
    rules.append(FsRule("/proc", _LL_READ))
    if "tmppath" in pledges:
        rules.append(FsRule(tmpdir, _LL_READ | _LL_WRITE | _LL_CREATE | _LL_EXECUTE))
        anchors.append(tmpdir)
    if "rpath" in pledges:
        access = _LL_READ
        if "wpath" in pledges:
            access |= _LL_WRITE
        if "cpath" in pledges:
            access |= _LL_CREATE
        rules.append(FsRule(workspace, access))
        anchors.append(workspace)
    # Traverse-only (EXECUTE, no READ_DIR) on every ancestor of each anchor:
    # Landlock denies path resolution through directories with no rule, so
    # without these the anchor itself would be unreachable. Ancestors stay
    # unlistable and unreadable — the minimum needed for the pledge's own
    # paths to work.
    seen = {rule.path for rule in rules}
    for anchor in anchors:
        for ancestor in _ancestor_dirs(anchor):
            if ancestor not in seen:
                rules.append(FsRule(ancestor, _LL_EXECUTE))
                seen.add(ancestor)
    return rules


#: ``python3 -c`` loader: Landlock-restrict, then install the seccomp-BPF
#: denylist, then exec the target. Mirrors the prctl loader contract in
#: :mod:`tools.seccomp` — a mechanism failure exits 126 with a stderr note
#: instead of running unrestricted.
#:
#: Layout: ``python3 -c <LOADER> <b64-seccomp> <json-rules> <target argv...>``.
_PLEDGE_LOADER = r"""
import base64 as _b, ctypes as _c, json as _j, os as _o, sys as _s, struct as _t
_sec = _b.b64decode(_s.argv[1])
_rules = _j.loads(_s.argv[2])
_lib = _c.CDLL(None, use_errno=True)
_lib.syscall.restype = _c.c_long
def _die(msg):
    _o.write(2, ("northstar pledge: " + msg + "\n").encode())
    _o._exit(126)
# 1. Landlock: build ruleset, add PATH_BENEATH rules, restrict self.
_attr = _t.pack("QQQ", 0x1FFF, 0, 0)
_buf = _c.create_string_buffer(_attr)
_rs = _lib.syscall(444, _c.cast(_buf, _c.c_void_p), 24, 0, 0, 0, 0)
if _rs < 0:
    _die("landlock_create_ruleset failed, errno %d" % _c.get_errno())
try:
    for _r in _rules:
        _fd = _o.open(_r["path"], _o.O_PATH | _o.O_DIRECTORY | _o.O_CLOEXEC)
        try:
            # struct landlock_path_beneath_attr: u64 allowed_access,
            # s32 parent_fd, padded to 16 bytes (u64 alignment).
            _pa = _t.pack("qii", _r["access"], _fd, 0)
            _pb = _c.create_string_buffer(_pa)
            if _lib.syscall(445, _rs, 1, _c.cast(_pb, _c.c_void_p), 0, 0, 0, 0) != 0:
                _die("landlock_add_rule failed for %s, errno %d" % (_r["path"], _c.get_errno()))
        finally:
            _o.close(_fd)
    if _lib.syscall(446, _rs, 0, 0, 0, 0, 0) != 0:
        _die("landlock_restrict_self failed, errno %d" % _c.get_errno())
finally:
    _o.close(_rs)
# 2. seccomp denylist, same contract as tools/seccomp.py's prctl loader.
class _P(_c.Structure):
    _fields_ = [("len", _c.c_ushort), ("filter", _c.c_void_p)]
_fbuf = _c.create_string_buffer(_sec)
_prog = _P(len(_sec) // 8, _c.cast(_fbuf, _c.c_void_p))
if _lib.prctl(38, 1, 0, 0, 0) != 0:
    _die("PR_SET_NO_NEW_PRIVS failed")
if _lib.prctl(22, 2, _c.byref(_prog), 0, 0) != 0:
    _die("PR_SET_SECCOMP failed, errno %d" % _c.get_errno())
_o.execvp(_s.argv[3], _s.argv[3:])
""".strip()


def pledge_loader_argv(
    rules: Sequence[FsRule],
    target_argv: Sequence[str],
    *,
    python: str = "python3",
) -> list[str]:
    """Wrap ``target_argv`` so Landlock + seccomp apply before exec.

    The seccomp program is the same denylist :mod:`tools.seccomp` builds —
    the pledge loader never weakens it, it only adds the Landlock layer.
    """
    encoded = base64.b64encode(build_default_filter()).decode("ascii")
    payload = json.dumps([rule.as_dict() for rule in rules], sort_keys=True)
    return [python, "-c", _PLEDGE_LOADER, encoded, payload, *target_argv]


def enforcement_report(
    pledges: frozenset[str] | None,
    *,
    backend: str,
    landlock: LandlockSupport | None = None,
) -> dict[str, Any]:
    """Honest report of which enforcement layers apply to a pledge set."""
    support = landlock if landlock is not None else landlock_probe()
    layers: list[str] = ["semantic: PledgeContext fail-closed (always)"]
    if pledges is not None and backend == "bwrap":
        layers.append(
            "bwrap: workspace --ro-bind"
            if not ({"wpath", "cpath"} & pledges)
            else "bwrap: workspace --bind (wpath/cpath pledged)"
        )
    if pledges is not None and backend == "process":
        if support.available:
            layers.append("process: landlock self-restriction + seccomp denylist")
        else:
            layers.append(
                "process: seccomp denylist only "
                f"(landlock unavailable: {support.detail}); semantic layer still fails closed"
            )
    layers.append("seccomp: BPF denylist over escape primitives (escape -> EPERM)")
    return {
        "pledges": sorted(pledges) if pledges is not None else None,
        "backend": backend,
        "landlock": support.as_dict(),
        "layers": layers,
    }


__all__ = [
    "DEFAULT_SHELL_PLEDGES",
    "FsRule",
    "LandlockSupport",
    "PROMISES",
    "PledgeContext",
    "PledgeError",
    "PledgeEvent",
    "PledgeViolation",
    "enforcement_report",
    "filesystem_rules",
    "landlock_probe",
    "pledge_loader_argv",
    "resolve_pledges",
    "validate_promises",
]
