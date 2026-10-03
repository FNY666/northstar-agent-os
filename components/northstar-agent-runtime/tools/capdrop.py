"""Linux capability minimisation launcher for tool-effect subprocesses.

Absorbs the Linux capabilities(7) model into the tool-effect layer: before a
tool-effect subprocess execs, the launcher drops the calling thread's
capabilities down to an explicit whitelist (default: empty — deny-all) and
makes the drop as irreversible as the host allows. A model that talks its way
into a shell still gets a bare, capability-less process.

Semantics, each verified against primary sources rather than memory:

* ``capabilities(7)`` — *"Programmatically adjusting capability sets"*: a
  thread can always *drop* capabilities from its own effective / permitted /
  inheritable sets via capset(2); the new permitted set must be a subset of
  the existing one, so a whitelist can only ever *retain* capabilities the
  parent already held — privilege is never fabricated.
* ``capabilities(7)`` — *"Capability bounding set"*: shrinking the bounding
  set needs ``prctl(PR_CAPBSET_DROP)`` **with CAP_SETPCAP**, and the drop is
  irreversible. The bounding set masks file *permitted* capabilities but
  *not* the inheritable set, so the launcher also zeroes the inheritable
  set — otherwise a dropped capability could be regained by execing a file
  that carries it as inheritable.
* Ambient capabilities are cleared with ``PR_CAP_AMBIENT_CLEAR_ALL`` (no
  privilege required); ambient is the one set that auto-raises permitted on
  exec, so leaving it would silently re-grant.
* ``capabilities(7)`` — *"The securebits flags"*: ``SECBIT_NOROOT`` /
  ``SECBIT_NO_SETUID_FIXUP`` (locked) stop set-user-ID-root exec and UID 0
  transitions from re-granting privilege; changing securebits also needs
  CAP_SETPCAP. Without it the launcher records EPERM and continues — the
  effective/permitted/inheritable/ambient zeroing is the actual enforcement;
  bounding-set and securebits steps are irreversibility hardening.
* Capability numbers 0..40 (``CAP_CHOWN``..``CAP_CHECKPOINT_RESTORE``) are
  taken from ``/usr/include/linux/capability.h`` (``CAP_LAST_CAP``); prctl
  constants from ``/usr/include/linux/prctl.h``; securebits from
  ``/usr/include/linux/securebits.h``; capset syscall numbers from the
  kernel ``unistd`` tables (x86_64 125/126, aarch64 90/91).

Integration mirrors ``tools/seccomp.py`` — no ``Popen(preexec_fn=...)``,
which is unsafe in the threaded runtime:

* process backend: :func:`capdrop_loader_argv` wraps the target argv in a
  ``python3 -c`` loader that applies the policy, writes a JSON audit report
  to a dedicated fd, then execs. A policy-application failure exits 126
  instead of running the command un-dropped (fail-closed, like the seccomp
  loader). Bounding/securebits EPERM from a host without CAP_SETPCAP is
  *not* fatal — it is recorded in the report.
* bwrap backend: ``--cap-drop ALL`` plus ``--cap-add`` per whitelist entry
  (``bwrap(1)``: the two are processed in command-line order), applied when
  the probe finds the binary advertising ``--cap-drop``.

The audit report (before/after capability sets, per-operation results) comes
back on the report fd and is attached to ``SandboxResult.capdrop`` — an
escalation attempt (re-raising a dropped capability) fails with EPERM, which
the ``metrics.capdrop`` bench case observes directly.
"""
from __future__ import annotations

import base64
import json
import platform
from dataclasses import dataclass
from typing import Sequence

#: Capability name -> bit number, from /usr/include/linux/capability.h
#: (CAP_LAST_CAP = CAP_CHECKPOINT_RESTORE = 40). Do not extend from memory.
CAPABILITIES: dict[str, int] = {
    "CAP_CHOWN": 0,
    "CAP_DAC_OVERRIDE": 1,
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_FOWNER": 3,
    "CAP_FSETID": 4,
    "CAP_KILL": 5,
    "CAP_SETGID": 6,
    "CAP_SETUID": 7,
    "CAP_SETPCAP": 8,
    "CAP_LINUX_IMMUTABLE": 9,
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_BROADCAST": 11,
    "CAP_NET_ADMIN": 12,
    "CAP_NET_RAW": 13,
    "CAP_IPC_LOCK": 14,
    "CAP_IPC_OWNER": 15,
    "CAP_SYS_MODULE": 16,
    "CAP_SYS_RAWIO": 17,
    "CAP_SYS_CHROOT": 18,
    "CAP_SYS_PTRACE": 19,
    "CAP_SYS_PACCT": 20,
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_BOOT": 22,
    "CAP_SYS_NICE": 23,
    "CAP_SYS_RESOURCE": 24,
    "CAP_SYS_TIME": 25,
    "CAP_SYS_TTY_CONFIG": 26,
    "CAP_MKNOD": 27,
    "CAP_LEASE": 28,
    "CAP_AUDIT_WRITE": 29,
    "CAP_AUDIT_CONTROL": 30,
    "CAP_SETFCAP": 31,
    "CAP_MAC_OVERRIDE": 32,
    "CAP_MAC_ADMIN": 33,
    "CAP_SYSLOG": 34,
    "CAP_WAKE_ALARM": 35,
    "CAP_BLOCK_SUSPEND": 36,
    "CAP_AUDIT_READ": 37,
    "CAP_PERFMON": 38,
    "CAP_BPF": 39,
    "CAP_CHECKPOINT_RESTORE": 40,
}

#: Highest capability bit the launcher knows how to drop (inclusive).
CAP_LAST_BIT = 40

#: prctl(2) constants, from /usr/include/linux/prctl.h.
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_PR_CAPBSET_DROP = 24
_PR_SET_SECUREBITS = 28

#: securebits lock mask: SECBIT_NOROOT(+LOCKED) | SECBIT_NO_SETUID_FIXUP(+LOCKED)
#: | SECBIT_NO_CAP_AMBIENT_RAISE(+LOCKED), from /usr/include/linux/securebits.h.
#: KEEP_CAPS is deliberately left off (the man page's own lock recipe).
_SECBIT_LOCK = 0x01 | 0x02 | 0x04 | 0x08 | 0x40 | 0x80

#: capset/capget syscall numbers per arch, from the kernel unistd tables.
_CAPSET_NR = {"x86_64": 126, "aarch64": 91}

#: /proc/self/status field -> report key.
_STATUS_FIELDS = {
    "CapInh": "inheritable",
    "CapPrm": "permitted",
    "CapEff": "effective",
    "CapBnd": "bounding",
    "CapAmb": "ambient",
}

_ZERO_SET = "0000000000000000"


class CapDropError(ValueError):
    """Invalid capability policy or an unsatisfiable drop requirement."""


@dataclass(frozen=True)
class CapDropPolicy:
    """Whitelist of capability names retained across the drop.

    Empty (the default) means deny-all. A name outside :data:`CAPABILITIES`
    is rejected at parse time; a whitelisted capability the launcher process
    does not itself hold fails closed at apply time (fail-closed beats
    silently running wider than the operator asked).
    """

    whitelist: frozenset[str] = frozenset()

    def numbers(self) -> tuple[int, ...]:
        """Whitelist as sorted capability bit numbers (what the loader takes)."""
        return tuple(sorted(CAPABILITIES[name] for name in self.whitelist))


def parse_whitelist(spec: object) -> frozenset[str]:
    """Parse a whitelist from None / "" / comma string / sequence of names."""
    if spec is None:
        return frozenset()
    if isinstance(spec, str):
        items: Sequence[object] = [part.strip() for part in spec.split(",")]
    elif isinstance(spec, (list, tuple, set, frozenset)):
        items = list(spec)
    else:
        raise CapDropError(
            f"capability whitelist must be None, a string, or a sequence of "
            f"CAP_* names, got {type(spec).__name__}"
        )
    names = set()
    for item in items:
        if not isinstance(item, str) or not item:
            if item == "":
                continue
            raise CapDropError(f"capability names must be non-empty strings, got {item!r}")
        names.add(item)
    unknown = sorted(names - CAPABILITIES.keys())
    if unknown:
        raise CapDropError(
            f"unknown capability names: {', '.join(unknown)}; "
            f"choose from {', '.join(sorted(CAPABILITIES))}"
        )
    return frozenset(names)


def resolve_capdrop(payload_value: object, service_value: object) -> tuple[str, ...] | None:
    """Merge a per-call payload value with the operator-configured service value.

    Tighten-only, mirroring ``tools.seccomp.resolve_mode``: the model may only
    *narrow* the whitelist, never widen it or switch the launcher off.

    * service ``"off"`` (or ``False``) disables the launcher; the payload is
      then ignored entirely (operator escape hatch).
    * service ``None``/``"on"``/``True`` means deny-all; a payload whitelist
      intersects it (still deny-all unless the service named caps).
    * payload ``"off"`` is ignored unless the service is off — a tool call
      cannot re-enable privilege the operator removed.
    * any other payload value must be a subset of the service whitelist;
      effective = intersection.

    Returns the effective whitelist as a sorted tuple, or ``None`` when the
    launcher is disabled.
    """
    if service_value in ("off", False):
        return None
    if service_value in (None, "on", True):
        service_set: frozenset[str] = frozenset()
    else:
        service_set = parse_whitelist(service_value)
    if payload_value is None:
        effective = service_set
    elif payload_value in ("on", True):
        effective = frozenset()
    elif payload_value in ("off", False):
        effective = service_set  # tighten-only: a call cannot disable the drop
    else:
        effective = service_set & parse_whitelist(payload_value)
    return tuple(sorted(effective))


def read_capability_sets() -> dict[str, int]:
    """Read this thread's five capability sets from /proc/self/status."""
    sets: dict[str, int] = {}
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.startswith("Cap"):
                    continue
                field, _, value = line.partition(":")
                key = _STATUS_FIELDS.get(field.strip())
                if key is not None:
                    sets[key] = int(value.strip(), 16)
    except OSError as error:
        raise CapDropError(f"cannot read /proc/self/status: {error}") from error
    if set(sets) != set(_STATUS_FIELDS.values()):
        raise CapDropError(f"could not read all five capability sets: {sorted(sets)}")
    return sets


def capability_sets_zero(sets: dict[str, int]) -> bool:
    """True when every capability set in ``sets`` is empty."""
    return all(value == 0 for value in sets.values())


def drop_report_enforced(report: object) -> bool:
    """Check enforced sets and account for every best-effort bounding drop.

    Bounding/securebits EPERM is permitted only when explicitly audited. This
    is not a claim that all five sets are zero or that arbitrary exec is safe.
    """
    if not isinstance(report, dict) or report.get("errors") != []:
        return False
    try:
        whitelist = report["whitelist"]
        if not isinstance(whitelist, list) or any(type(cap) is not int or not 0 <= cap <= CAP_LAST_BIT for cap in whitelist):
            return False
        mask = sum(1 << cap for cap in set(whitelist))
        before = {key: int(report["before"][key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
        after = {key: int(report["after"][key], 16) for key in before}
        if any(value < 0 or value >= 1 << 64 for value in (*before.values(), *after.values())):
            return False
        if mask & ~before["CapPrm"]:
            return False
        if any(after[key] != mask for key in ("CapInh", "CapPrm", "CapEff")) or after["CapAmb"] != 0:
            return False
        ops = report["ops"]
        if not isinstance(ops, list) or not all(isinstance(op, dict) for op in ops):
            return False
        if any(op.get("op") not in {"ambient_clear", "capset", "bounding_drop", "securebits"} for op in ops):
            return False
        for required in ("capset", "ambient_clear"):
            matched = [op for op in ops if op.get("op") == required]
            if len(matched) != 1 or matched[0].get("ok") is not True:
                return False
        secure = [op for op in ops if op.get("op") == "securebits"]
        if len(secure) != 1 or not (secure[0].get("ok") is True or
            (secure[0].get("ok") is False and str(secure[0].get("detail", "")).startswith("errno 1 "))):
            return False
        dropped, denied = set(), set()
        for op in [op for op in ops if op.get("op") == "bounding_drop"]:
            detail = str(op.get("detail", ""))
            if op.get("ok") is True and detail.startswith("dropped="):
                dest = dropped
            elif op.get("ok") is False and detail.startswith("eperm="):
                dest = denied
            else:
                return False
            values = detail.split("=", 1)[1]
            parsed = [int(value) for value in values.split(",")] if values else []
            if len(set(parsed)) != len(parsed) or dest.intersection(parsed):
                return False
            dest.update(parsed)
        expected = set(range(CAP_LAST_BIT + 1)) - set(whitelist)
        if dropped & denied or dropped | denied != expected:
            return False
        dropped_mask = sum(1 << cap for cap in dropped)
        if after["CapBnd"] != before["CapBnd"] & ~dropped_mask:
            return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def summarize_report(report: dict[str, object]) -> str:
    """One-line human/model-facing summary of a loader audit report."""
    whitelist = report.get("whitelist", [])
    after = report.get("after", {})
    if not isinstance(after, dict):
        after = {}
    zeroed = sorted(
        name for name, value in after.items() if value == _ZERO_SET
    )
    ops = report.get("ops", [])
    bounding_dropped = bounding_eperm = 0
    securebits = "n/a"
    if isinstance(ops, list):
        for op in ops:
            if not isinstance(op, dict):
                continue
            if op.get("op") == "bounding_drop":
                detail = str(op.get("detail", ""))
                if detail.startswith("dropped="):
                    bounding_dropped = len(detail.split("=", 1)[1].split(",")) if detail.split("=", 1)[1] else 0
                elif detail.startswith("eperm="):
                    bounding_eperm = len(detail.split("=", 1)[1].split(",")) if detail.split("=", 1)[1] else 0
            elif op.get("op") == "securebits":
                securebits = "locked" if op.get("ok") else f"EPERM ({op.get('detail', '')})"
    scope = "deny-all" if not whitelist else f"whitelist={','.join(sorted(str(w) for w in whitelist))}"
    return (
        f"capdrop {scope}: zeroed sets {','.join(zeroed) or 'none'}; "
        f"bounding dropped {bounding_dropped}, EPERM {bounding_eperm}; "
        f"securebits {securebits}"
    )


#: A ``python3 -c`` loader that drops capabilities via capset/prctl and then
#: execs the real command. Self-contained (ctypes only) so the child needs no
#: import path — same rationale as the seccomp prctl loader.
#:
#: Layout: ``python3 -c <LOADER> <base64-json-config> <target argv...>`` with
#: config ``{"whitelist": [cap numbers], "fd": report_fd}``. The JSON audit
#: report goes to the report fd, which the parent passes via ``pass_fds``.
#: Any policy-application failure exits 126 without running the target
#: (fail-closed); bounding-set/securebits EPERM from a host without
#: CAP_SETPCAP is recorded, not fatal.
#:
#: Application order matters and follows capabilities(7): ambient is cleared
#: first (no privilege needed), then the bounding set is shrunk *while*
#: CAP_SETPCAP is still held, then securebits are locked, and only then are
#: effective/permitted/inheritable zeroed via capset(2) — dropping needs no
#: privilege, so this step cannot fail on privilege grounds.
_CAPDROP_LOADER = r"""
import base64 as _b, ctypes as _c, json as _j, os as _o, platform as _p, sys as _s
_cfg = _j.loads(_b.b64decode(_s.argv[1]).decode("utf-8"))
_wl = _cfg["whitelist"]
_fd = _cfg["fd"]
_rep = {"whitelist": sorted(_wl), "ops": [], "errors": []}
def _rec(op, ok, detail=""):
    _rep["ops"].append({"op": op, "ok": ok, "detail": detail})
def _fail(msg):
    _rep["errors"].append(msg)
    try:
        _o.write(2, ("northstar: capdrop failed: %s\n" % msg).encode())
    except OSError:
        pass
    _o._exit(126)
def _read_sets():
    _d = {}
    with open("/proc/self/status", "r", encoding="utf-8") as _f:
        for _line in _f:
            if _line.startswith("Cap"):
                _k, _, _v = _line.partition(":")
                _d[_k.strip()] = _v.strip()
    return _d
try:
    _arch = _p.machine()
    _nr = {"x86_64": 126, "aarch64": 91}.get(_arch)
    if _nr is None:
        _fail("no capset syscall number for arch %r" % (_arch,))
    _libc = _c.CDLL(None, use_errno=True)
    _rep["before"] = _read_sets()
    # 1. Ambient clear — no privilege required.
    if _libc.prctl(47, 4, 0, 0, 0) != 0:
        _fail("PR_CAP_AMBIENT_CLEAR_ALL failed, errno %d" % _c.get_errno())
    _rec("ambient_clear", True)
    # 2. Bounding set — needs CAP_SETPCAP; EPERM is recorded, not fatal.
    _dropped, _denied, _other = [], [], []
    for _cap in range(41):
        if _cap in _wl:
            continue
        if _libc.prctl(24, _cap, 0, 0, 0) == 0:
            _dropped.append(_cap)
        else:
            _e = _c.get_errno()
            if _e == 1:
                _denied.append(_cap)
            else:
                _other.append((_cap, _e))
    _rec("bounding_drop", True, "dropped=%s" % ",".join(str(c) for c in _dropped))
    if _denied:
        _rec("bounding_drop", False, "eperm=%s" % ",".join(str(c) for c in _denied))
    for _cap, _e in _other:
        _rec("bounding_drop", False, "cap=%d errno=%d" % (_cap, _e))
    # 3. Securebits lock — needs CAP_SETPCAP; EPERM is recorded, not fatal.
    _sb = 0x01 | 0x02 | 0x04 | 0x08 | 0x40 | 0x80
    if _libc.prctl(28, _sb, 0, 0, 0) != 0:
        _rec("securebits", False, "errno %d (needs CAP_SETPCAP)" % _c.get_errno())
    else:
        _rec("securebits", True, "0x%02x locked" % _sb)
    # 4. capset: eff=prm=inh=whitelist. Dropping needs no privilege; raising
    #    beyond what the thread holds fails EPERM -> fail closed (loud).
    class _H(_c.Structure):
        _fields_ = [("version", _c.c_uint32), ("pid", _c.c_int)]
    class _D(_c.Structure):
        _fields_ = [("effective", _c.c_uint32), ("permitted", _c.c_uint32), ("inheritable", _c.c_uint32)]
    _lo = _hi = 0
    for _cap in _wl:
        if _cap < 32:
            _lo |= 1 << _cap
        else:
            _hi |= 1 << (_cap - 32)
    _hdr = _H(0x20080522, 0)
    _dat = (_D * 2)((_D(_lo, _lo, _lo)), (_D(_hi, _hi, _hi)))
    if _libc.syscall(_nr, _c.byref(_hdr), _c.byref(_dat)) != 0:
        _fail("capset failed, errno %d (whitelist holds a cap this process lacks?)" % _c.get_errno())
    _rec("capset", True, "eff/prm/inh=%08x/%08x" % (_lo, _hi))
    _rep["after"] = _read_sets()
    _o.write(_fd, (_j.dumps(_rep) + "\n").encode())
    _o.close(_fd)
except Exception as _e:  # noqa: BLE001 - loader must never run the target on error
    _fail("%s: %s" % (type(_e).__name__, _e))
_o.execvp(_s.argv[2], _s.argv[2:])
""".strip()


def capdrop_loader_argv(
    target_argv: Sequence[str],
    whitelist: Sequence[str] | Sequence[int] | CapDropPolicy,
    *,
    fd: int,
    python: str = "python3",
) -> list[str]:
    """Wrap ``target_argv`` so capabilities are dropped before exec.

    Returns ``[python, "-c", LOADER, b64(config), *target_argv]`` where the
    config carries the whitelist as capability *numbers* and the report fd.
    ``whitelist`` accepts names, numbers, or a :class:`CapDropPolicy`.
    """
    if isinstance(whitelist, CapDropPolicy):
        numbers = list(whitelist.numbers())
    else:
        numbers = []
        for item in whitelist:
            if isinstance(item, int):
                if not 0 <= item <= CAP_LAST_BIT:
                    raise CapDropError(f"capability bit out of range: {item}")
                numbers.append(item)
            elif isinstance(item, str):
                if item not in CAPABILITIES:
                    raise CapDropError(f"unknown capability name: {item!r}")
                numbers.append(CAPABILITIES[item])
            else:
                raise CapDropError(
                    f"whitelist entries must be CAP_* names or bit numbers, "
                    f"got {item!r}"
                )
    config = base64.b64encode(
        json.dumps({"whitelist": sorted(set(numbers)), "fd": fd}).encode("utf-8")
    ).decode("ascii")
    return [python, "-c", _CAPDROP_LOADER, config, *target_argv]


def bwrap_capability_args(whitelist: Sequence[str]) -> list[str]:
    """bwrap ``--cap-drop``/``--cap-add`` args for a whitelist.

    ``--cap-drop ALL`` first, then one ``--cap-add`` per whitelisted name;
    ``bwrap(1)`` processes the two in command-line order, so the adds survive
    the drop.
    """
    args = ["--cap-drop", "ALL"]
    for name in whitelist:
        if name not in CAPABILITIES:
            raise CapDropError(f"unknown capability name: {name!r}")
        args.extend(["--cap-add", name])
    return args


__all__ = [
    "CAPABILITIES",
    "CAP_LAST_BIT",
    "CapDropError",
    "CapDropPolicy",
    "bwrap_capability_args",
    "capability_sets_zero",
    "capdrop_loader_argv",
    "drop_report_enforced",
    "parse_whitelist",
    "read_capability_sets",
    "resolve_capdrop",
    "summarize_report",
]
