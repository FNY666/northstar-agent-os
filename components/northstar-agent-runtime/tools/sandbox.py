"""Linux Landlock unprivileged self-sandbox for the process backend.

Landlock (Linux 5.13+) lets an *unprivileged* process restrict its own
filesystem and network access — no root, no capabilities, no user namespaces.
The ritual, per ``docs.kernel.org/userspace-api/landlock``:

1. ``landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`` —
   returns the kernel ABI version (negative = unsupported: degrade gracefully);
2. build the ruleset, masking handled rights against the running ABI
   (best-effort pattern from the same document);
3. ``landlock_add_rule`` — one ``LANDLOCK_RULE_PATH_BENEATH`` per whitelisted
   hierarchy (opened ``O_PATH``), plus optional ``LANDLOCK_RULE_NET_PORT``
   rules;
4. ``prctl(PR_SET_NO_NEW_PRIVS, 1)`` (required for unprivileged use below
   ABI 11), then ``landlock_restrict_self(ruleset_fd, flags)``.

Three properties make it the right complement to ``tools/seccomp.py``:

* **Irreversible** — once landlocked, a thread can only *add* restrictions,
  never remove them. A compromised tool subprocess cannot un-sandbox itself.
* **Inherited** — the domain covers the process and all its future children.
* **Stackable** — each ``restrict_self`` merges a new layer over the parent
  domain; layers only ever tighten.

So Landlock is the *path* layer and seccomp-BPF is the *syscall* layer: a
tool-effect subprocess on the process backend gets both. The two wrappers
compose as nested ``python3 -c`` loaders (Landlock outside, seccomp inside),
exactly like the existing prctl loader — fresh single-threaded interpreters,
so there is no ``Popen(preexec_fn=...)`` fork-in-threads hazard.

Access-right bit values below were verified against
``/usr/include/linux/landlock.h`` on the build host and behaviorally (a
whitelist denying ``/tmp`` writes really denies them with ``EACCES``), not
taken from memory. Rights that arrived after an ABI are masked out when the
running kernel is older (docs.kernel.org compatibility switch):

* ``REFER`` — ABI 2+; ``TRUNCATE`` — ABI 3+; TCP ``BIND``/``CONNECT`` — ABI 4+;
  ``IOCTL_DEV`` — ABI 5+; ``RESOLVE_UNIX`` — ABI 9+; UDP rights — ABI 10+.
* ``LANDLOCK_RESTRICT_SELF_TSYNC`` — ABI 8+ (without it, ``restrict_self``
  only covers the calling thread; our loader is single-threaded either way).

Graceful degradation: when the kernel lacks Landlock, mode ``auto`` emits an
explicit stderr warning and continues with the seccomp layer alone
(fail-closed *to* seccomp — never to nothing). Mode ``on`` refuses to run
without Landlock, mirroring ``seccomp="on"`` semantics.
"""
from __future__ import annotations

import base64
import json
import sys
from typing import Mapping, Sequence

#: Operator-facing modes, mirroring tools/seccomp.py. ``auto`` applies the
#: allowlist whenever the kernel supports Landlock and degrades (with a loud
#: warning) to seccomp-only otherwise; ``on`` requires Landlock and refuses
#: to run without it; ``off`` disables it.
LANDLOCK_MODES = ("auto", "on", "off")

_STRICTNESS = {"off": 0, "auto": 1, "on": 2}

# landlock(2) numbers, x86_64 — verified against
# /usr/include/x86_64-linux-gnu/asm/unistd_64.h on the build host.
_NR_CREATE_RULESET = 444
_NR_ADD_RULE = 445
_NR_RESTRICT_SELF = 446
_CREATE_RULESET_VERSION = 1  # LANDLOCK_CREATE_RULESET_VERSION

_RULE_PATH_BENEATH = 1
_RULE_NET_PORT = 2

# Filesystem access rights, bit positions from include/uapi/linux/landlock.h.
# Rights introduced after an ABI are listed with their minimum ABI; the loader
# masks them out on older kernels.
_FS_RIGHTS: tuple[tuple[str, int, int], ...] = (
    ("EXECUTE", 1 << 0, 1),
    ("WRITE_FILE", 1 << 1, 1),
    ("READ_FILE", 1 << 2, 1),
    ("READ_DIR", 1 << 3, 1),
    ("REMOVE_DIR", 1 << 4, 1),
    ("REMOVE_FILE", 1 << 5, 1),
    ("MAKE_CHAR", 1 << 6, 1),
    ("MAKE_DIR", 1 << 7, 1),
    ("MAKE_REG", 1 << 8, 1),
    ("MAKE_SOCK", 1 << 9, 1),
    ("MAKE_FIFO", 1 << 10, 1),
    ("MAKE_BLOCK", 1 << 11, 1),
    ("MAKE_SYM", 1 << 12, 1),
    ("REFER", 1 << 13, 2),
    ("TRUNCATE", 1 << 14, 3),
    ("IOCTL_DEV", 1 << 15, 5),
    ("RESOLVE_UNIX", 1 << 16, 9),
)

_NET_RIGHTS: tuple[tuple[str, int, int], ...] = (
    ("BIND_TCP", 1 << 0, 4),
    ("CONNECT_TCP", 1 << 1, 4),
    ("BIND_UDP", 1 << 2, 10),
    ("CONNECT_SEND_UDP", 1 << 3, 10),
)

#: Filesystem rights handled by the default deny-by-default ruleset: every
#: access a tool subprocess needs is granted explicitly per path; anything
#: else is denied.
_DEFAULT_HANDLED_FS = (
    "EXECUTE",
    "WRITE_FILE",
    "READ_FILE",
    "READ_DIR",
    "REMOVE_DIR",
    "REMOVE_FILE",
    "MAKE_CHAR",
    "MAKE_DIR",
    "MAKE_REG",
    "MAKE_SOCK",
    "MAKE_FIFO",
    "MAKE_BLOCK",
    "MAKE_SYM",
    "REFER",
    "TRUNCATE",
    "IOCTL_DEV",
)

#: Rights granted on system binary/library hierarchies (read + execute).
_BIN_RIGHTS = ("EXECUTE", "READ_FILE", "READ_DIR")

#: Rights granted on /etc and /proc (read-only data).
_DATA_RIGHTS = ("READ_FILE", "READ_DIR")

#: Rights granted on /dev (devices are opened, never created, by tools).
_DEV_RIGHTS = ("READ_FILE", "READ_DIR", "WRITE_FILE")

#: Rights granted on the workspace: full read/write/execute, minus device
#: and socket creation (no MAKE_CHAR/MAKE_BLOCK/MAKE_SOCK).
_WORKSPACE_RIGHTS = (
    "EXECUTE",
    "WRITE_FILE",
    "READ_FILE",
    "READ_DIR",
    "REMOVE_DIR",
    "REMOVE_FILE",
    "MAKE_DIR",
    "MAKE_REG",
    "MAKE_FIFO",
    "MAKE_SYM",
    "REFER",
    "TRUNCATE",
)

#: System hierarchies a tool subprocess may always see (filtered to those
#: that actually exist on the host at spec-build time).
_SYSTEM_READ_PATHS = ("/usr", "/bin", "/lib", "/lib64", "/sbin")


def _runtime_read_paths() -> tuple[str, ...]:
    """Existing runtime directories only; never widen to their /opt/home parents."""
    import os
    import sysconfig

    candidates = [os.path.dirname(os.path.realpath(sys.executable))]
    for prefix in {sys.prefix, sys.base_prefix}:
        candidates.extend(os.path.join(prefix, part) for part in ("bin", "lib", "lib64"))
    candidates.extend(sysconfig.get_path(key) for key in ("stdlib", "platstdlib"))
    extra = [os.path.realpath(path) for path in candidates if path and os.path.isdir(path)]
    return tuple(dict.fromkeys([*_SYSTEM_READ_PATHS, *extra]))


class LandlockError(ValueError):
    """Invalid Landlock mode or an unsatisfiable Landlock requirement."""


def validate_mode(mode: str) -> str:
    """Normalise an operator/model Landlock mode; raise on unknown values."""
    if not isinstance(mode, str):
        raise LandlockError(
            f"landlock mode must be a string, got {type(mode).__name__}; "
            f"choose one of {', '.join(LANDLOCK_MODES)}"
        )
    name = mode.strip().lower() or "auto"
    if name not in LANDLOCK_MODES:
        raise LandlockError(
            f"unknown landlock mode {mode!r}; choose one of {', '.join(LANDLOCK_MODES)}"
        )
    return name


def resolve_mode(payload_value: str | None, service_value: str | None) -> str:
    """Merge a per-call payload value with the operator-configured service value.

    Tighten-only: the call may move toward ``on`` but never away from what the
    operator configured. ``service="on"`` + ``payload="off"`` stays ``on``.
    """
    service = validate_mode(service_value or "auto")
    requested = validate_mode(payload_value if payload_value is not None else service)
    if _STRICTNESS[requested] >= _STRICTNESS[service]:
        return requested
    return service


def rights_mask(names: Sequence[str], table: Sequence[tuple[str, int, int]], abi: int) -> int:
    """OR the bit values of ``names`` that the running ABI actually supports."""
    bits = {name: (bit, min_abi) for name, bit, min_abi in table}
    mask = 0
    for name in names:
        bit, min_abi = bits[name]
        if abi >= min_abi:
            mask |= bit
    return mask


_ABI_CACHE: int | None = None


def landlock_abi_version() -> int:
    """Kernel Landlock ABI version, or 0 when the kernel lacks Landlock.

    The probe is ``landlock_create_ruleset(NULL, 0,
    LANDLOCK_CREATE_RULESET_VERSION)`` — the exact query the kernel
    documentation prescribes. Cached after the first call.
    """
    global _ABI_CACHE
    if _ABI_CACHE is not None:
        return _ABI_CACHE
    if not sys.platform.startswith("linux"):
        _ABI_CACHE = 0
        return 0
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        version = libc.syscall(_NR_CREATE_RULESET, None, 0, _CREATE_RULESET_VERSION)
        _ABI_CACHE = int(version) if int(version) > 0 else 0
    except Exception:
        _ABI_CACHE = 0
    return _ABI_CACHE


def reset_abi_cache() -> None:
    """Tests only: drop the cached ABI probe so a fixture can re-run it."""
    global _ABI_CACHE
    _ABI_CACHE = None


def landlock_supported() -> bool:
    """True when this kernel can enforce a Landlock ruleset."""
    return landlock_abi_version() > 0


def probe_landlock() -> dict:
    """Operator-facing capability report: supported / ABI / detail."""
    abi = landlock_abi_version()
    if abi > 0:
        return {
            "supported": True,
            "abi": abi,
            "detail": f"Landlock ABI v{abi} available (unprivileged self-sandbox)",
        }
    return {
        "supported": False,
        "abi": 0,
        "detail": "Landlock not supported by this kernel (needs Linux 5.13+ with CONFIG_SECURITY_LANDLOCK)",
    }


def build_landlock_spec(
    *,
    paths_read: Sequence[str],
    paths_write: Sequence[str],
    network: bool = False,
    tcp_ports: Sequence[int] = (),
    mode: str = "auto",
) -> dict:
    """Build an offline-testable Landlock policy spec.

    ``paths_read``/``paths_write`` are absolute directories; missing paths
    raise :class:`LandlockError` (fail-closed at build time — a whitelist
    that silently drops an entry would be a lie). ``network=False`` denies
    all TCP (the process backend's answer to bwrap's ``--unshare-net``);
    ``network=True`` opens exactly ``tcp_ports``.
    """
    mode = validate_mode(mode)
    if not isinstance(network, bool):
        raise LandlockError("network must be a bool")
    rules: list[dict] = []
    for path in paths_read:
        _check_dir(path, "paths_read")
        rules.append({"path": path, "rights": list(_BIN_RIGHTS)})
    for path in paths_write:
        _check_dir(path, "paths_write")
        rules.append({"path": path, "rights": list(_WORKSPACE_RIGHTS)})
    ports = []
    for port in tcp_ports:
        if not isinstance(port, int) or not (0 <= port <= 65535):
            raise LandlockError(f"tcp port must be an int in 0..65535, got {port!r}")
        ports.append(port)
    return {
        "mode": mode,
        "rules": rules,
        "network": network,
        "tcp_ports": ports,
    }


def _check_dir(path: str, field: str) -> None:
    import os

    if not isinstance(path, str) or not path.startswith("/"):
        raise LandlockError(f"{field} entries must be absolute paths, got {path!r}")
    if not os.path.isdir(path):
        raise LandlockError(f"{field} entry is not an existing directory: {path!r}")


def default_profile(workspace: str) -> dict:
    """The standard tool-effect profile: system read paths + writable workspace.

    ``/etc`` and ``/proc`` are read-only data; ``/dev`` allows opens (for
    ``/dev/null`` et al.) but no device creation. TCP is denied outright —
    the process backend's equivalent of bwrap's always-unshared network.
    """
    import os

    read_paths = [path for path in _runtime_read_paths() if os.path.isdir(path)]
    spec = build_landlock_spec(
        paths_read=read_paths,
        paths_write=[workspace],
        network=False,
    )
    # Narrow /etc, /proc, /dev from binary rights to their data/device rights.
    narrow = {
        "/etc": _DATA_RIGHTS,
        "/proc": _DATA_RIGHTS,
        "/dev": _DEV_RIGHTS,
    }
    extra = []
    for path, rights in narrow.items():
        if os.path.isdir(path):
            extra.append({"path": path, "rights": list(rights)})
    spec["rules"].extend(extra)
    return spec


def network_deny_profile() -> dict:
    """Network denial without filesystem confinement.

    Grants the whole tree the workspace rights (full read/write/execute,
    minus device and socket creation) and denies TCP outright (plus UDP on
    Landlock ABI 10+ kernels). The filesystem posture is unchanged from
    running unconfined -- the *only* thing this profile takes away is the
    network. For MCP servers: they are third-party binaries living anywhere
    on disk (npm/pip installs, fixture scripts outside any workspace), so
    the tool-effect path allowlist would break them for reasons unrelated
    to the gap being closed. The gap is egress; this closes exactly the gap.

    Note: AF_UNIX is not restrictable by Landlock; a denied-network process
    can still connect() to Unix sockets it can see on the filesystem. That
    residual is documented, not closed, by this profile.
    """
    spec = build_landlock_spec(
        paths_read=[],
        paths_write=["/"],
        network=False,
    )
    return spec


#: A ``python3 -c`` loader that installs the Landlock allowlist and then
#: execs the inner argv (normally the seccomp prctl wrapper). Layout:
#: ``python3 -c <LOADER> <base64-spec> <inner argv...>``.
#:
#: Failure semantics: mode ``on`` exits 126 with a stderr note (fail-closed —
#: the tool never runs unsandboxed when the operator demanded Landlock).
#: Mode ``auto`` writes an explicit WARNING to stderr and execs the inner
#: argv anyway, so the seccomp layer still applies: graceful degradation
#: that fails closed *to seccomp*, never to nothing.
_LANDLOCK_LOADER = r"""
import base64 as _b, ctypes as _c, json as _j, os as _o, struct as _st, sys as _s
_spec = _j.loads(_b.b64decode(_s.argv[1]).decode())
_mode = _spec.get("mode", "auto")
_inner = _s.argv[2:]
def _die(_m):
    _o.write(2, ("northstar: landlock: " + _m + "\n").encode())
    _o._exit(126)
def _warn(_m):
    _o.write(2, ("northstar: landlock WARNING: " + _m + " (seccomp layer still applies)\n").encode())
_lib = _c.CDLL("libc.so.6", use_errno=True)
_abi = _lib.syscall(444, None, 0, 1)
if _abi <= 0:
    if _mode == "on":
        _die("kernel does not support Landlock")
    _warn("kernel does not support Landlock")
    _o.execvp(_inner[0], _inner)
_FSR = {"EXECUTE":(1,1),"WRITE_FILE":(2,1),"READ_FILE":(4,1),"READ_DIR":(8,1),"REMOVE_DIR":(16,1),"REMOVE_FILE":(32,1),"MAKE_CHAR":(64,1),"MAKE_DIR":(128,1),"MAKE_REG":(256,1),"MAKE_SOCK":(512,1),"MAKE_FIFO":(1024,1),"MAKE_BLOCK":(2048,1),"MAKE_SYM":(4096,1),"REFER":(8192,2),"TRUNCATE":(16384,3),"IOCTL_DEV":(32768,5)}
_NETR = {"BIND_TCP":(1,4),"CONNECT_TCP":(2,4),"BIND_UDP":(4,10),"CONNECT_SEND_UDP":(8,10)}
def _mask(_names, _tab):
    _m = 0
    for _n in _names:
        _bit, _min = _tab[_n]
        if _abi >= _min:
            _m |= _bit
    return _m
_handled_fs = _mask(("EXECUTE","WRITE_FILE","READ_FILE","READ_DIR","REMOVE_DIR","REMOVE_FILE","MAKE_CHAR","MAKE_DIR","MAKE_REG","MAKE_SOCK","MAKE_FIFO","MAKE_BLOCK","MAKE_SYM","REFER","TRUNCATE","IOCTL_DEV"), _FSR)
_handled_net = _mask(("BIND_TCP","CONNECT_TCP","BIND_UDP","CONNECT_SEND_UDP"), _NETR)
_attr = _st.pack("<Q", _handled_fs) if _abi < 4 else _st.pack("<QQ", _handled_fs, _handled_net)
class _RA(_c.Structure):
    _fields_ = [("attr", _c.c_char_p), ("size", _c.c_size_t), ("flags", _c.c_uint32)]
_buf = _c.create_string_buffer(_attr)
_rs = _lib.syscall(444, _c.cast(_buf, _c.c_void_p), len(_attr), 0)
if _rs < 0:
    if _mode == "on":
        _die("landlock_create_ruleset failed")
    _warn("landlock_create_ruleset failed")
    _o.execvp(_inner[0], _inner)
class _PB(_c.Structure):
    _fields_ = [("allowed", _c.c_uint64), ("parent_fd", _c.c_int32)]
def _add_path(_path, _rights):
    _rights &= _handled_fs
    if not _rights:
        return
    _fd = _o.open(_path, _o.O_PATH | _o.O_CLOEXEC)
    try:
        _rule = _PB(_rights, _fd)
        if _lib.syscall(445, _rs, 1, _c.byref(_rule), 0) != 0:
            _warn("landlock_add_rule failed for " + _path)
    finally:
        _o.close(_fd)
for _r in _spec.get("rules", []):
    try:
        _add_path(_r["path"], _mask(_r["rights"], _FSR))
    except (OSError, KeyError) as _e:
        _warn("skipping rule for %s: %s" % (_r.get("path"), _e))
if _abi >= 4 and _spec.get("network"):
    class _NP(_c.Structure):
        _fields_ = [("allowed", _c.c_uint64), ("port", _c.c_uint16)]
    for _p in _spec.get("tcp_ports", []):
        for _rn in ("BIND_TCP", "CONNECT_TCP"):
            _rule = _NP(_mask((_rn,), _NETR), _p)
            _lib.syscall(445, _rs, 2, _c.byref(_rule), 0)
if _lib.prctl(38, 1, 0, 0, 0) != 0:
    _lib.close(_rs)
    if _mode == "on":
        _die("PR_SET_NO_NEW_PRIVS failed")
    _warn("PR_SET_NO_NEW_PRIVS failed")
    _o.execvp(_inner[0], _inner)
_flags = 1 if _abi >= 8 else 0
if _lib.syscall(446, _rs, _flags) != 0:
    _e = _c.get_errno()
    _lib.close(_rs)
    if _mode == "on":
        _die("landlock_restrict_self failed, errno %d" % _e)
    _warn("landlock_restrict_self failed, errno %d" % _e)
    _o.execvp(_inner[0], _inner)
_lib.close(_rs)
_o.execvp(_inner[0], _inner)
""".strip()


def landlock_loader_argv(
    inner_argv: Sequence[str],
    spec: Mapping[str, object],
    *,
    python: str = "python3",
) -> list[str]:
    """Wrap ``inner_argv`` so the Landlock allowlist is installed before exec.

    Returns ``[python, "-c", LOADER, b64(spec), *inner_argv]``. ``inner_argv``
    is normally the seccomp prctl wrapper's argv, giving the syscall layer
    (seccomp denylist) inside the path layer (Landlock allowlist). A Landlock
    failure exits 126 in mode ``on``; in mode ``auto`` it warns and execs the
    inner argv so seccomp still applies.
    """
    if not inner_argv:
        raise LandlockError("inner_argv must not be empty")
    encoded = base64.b64encode(json.dumps(spec, sort_keys=True).encode("utf-8")).decode("ascii")
    return [python, "-c", _LANDLOCK_LOADER, encoded, *inner_argv]


__all__ = [
    "LANDLOCK_MODES",
    "LandlockError",
    "build_landlock_spec",
    "default_profile",
    "landlock_abi_version",
    "landlock_loader_argv",
    "landlock_supported",
    "network_deny_profile",
    "probe_landlock",
    "reset_abi_cache",
    "resolve_mode",
    "rights_mask",
    "validate_mode",
]
