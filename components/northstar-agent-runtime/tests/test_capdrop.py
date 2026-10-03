"""Linux capability-drop launcher (tools/capdrop.py).

Unit tests pin the policy surface (whitelist parsing, tighten-only
resolution, loader argv shape, the 41-entry capability table); the live
subprocess tests prove the actual kernel behavior on Linux — deny-all leaves
all five sets zero, a whitelist never fabricates privilege, re-raising a
dropped capability fails EPERM, and a whitelist naming a capability the
process does not hold fails closed (126, target never runs).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

import support  # noqa: F401 — puts the runtime root on sys.path

from tools.capdrop import (
    CAPABILITIES,
    CAP_LAST_BIT,
    CapDropError,
    CapDropPolicy,
    bwrap_capability_args,
    capdrop_loader_argv,
    parse_whitelist,
    read_capability_sets,
    resolve_capdrop,
    summarize_report,
)

LINUX = sys.platform.startswith("linux")

#: Child script: print this process's five capability sets as JSON.
_READ_SETS_PY = (
    "import json; d = {}\n"
    "for line in open('/proc/self/status'):\n"
    "    k, _, v = line.partition(':')\n"
    "    k = k.strip()\n"
    "    if k.startswith('Cap'): d[k] = v.strip()\n"
    "print(json.dumps(d))"
)

#: Child script: try to re-raise CAP_SYS_ADMIN (bit 21) via capset(2);
#: print {"rc": ..., "errno": ...}. Must EPERM after a deny-all drop.
_ESCALATE_PY = (
    "import ctypes, json\n"
    "_l = ctypes.CDLL(None, use_errno=True)\n"
    "class H(ctypes.Structure):\n"
    "    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]\n"
    "class D(ctypes.Structure):\n"
    "    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]\n"
    "h = H(0x20080522, 0)\n"
    "d = (D * 2)((D(1 << 21, 1 << 21, 0)), (D(0, 0, 0)))\n"
    "rc = _l.syscall(126 if __import__('platform').machine() == 'x86_64' else 91,\n"
    "                ctypes.byref(h), ctypes.byref(d))\n"
    "print(json.dumps({'rc': rc, 'errno': ctypes.get_errno()}))"
)


def _run_loader(whitelist, child_py, timeout=30):
    """Run ``child_py`` under the capdrop loader; return (proc, report)."""
    read_fd, write_fd = os.pipe()
    argv = capdrop_loader_argv(["python3", "-c", child_py], whitelist, fd=write_fd)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, pass_fds=(write_fd,), timeout=timeout
        )
    finally:
        os.close(write_fd)
    with os.fdopen(read_fd, "r", encoding="utf-8") as handle:
        raw = handle.read()
    report = json.loads(raw) if raw.strip() else None
    return proc, report


class CapabilityTableTests(unittest.TestCase):
    def test_table_has_41_entries_numbered_0_to_40(self):
        self.assertEqual(len(CAPABILITIES), 41)
        self.assertEqual(sorted(CAPABILITIES.values()), list(range(41)))
        self.assertEqual(CAP_LAST_BIT, 40)

    def test_anchor_entries_match_kernel_header(self):
        # Spot checks against /usr/include/linux/capability.h.
        self.assertEqual(CAPABILITIES["CAP_CHOWN"], 0)
        self.assertEqual(CAPABILITIES["CAP_SETPCAP"], 8)
        self.assertEqual(CAPABILITIES["CAP_SYS_ADMIN"], 21)
        self.assertEqual(CAPABILITIES["CAP_BPF"], 39)
        self.assertEqual(CAPABILITIES["CAP_CHECKPOINT_RESTORE"], 40)


class ParseWhitelistTests(unittest.TestCase):
    def test_none_and_empty_mean_deny_all(self):
        self.assertEqual(parse_whitelist(None), frozenset())
        self.assertEqual(parse_whitelist(""), frozenset())
        self.assertEqual(parse_whitelist([]), frozenset())

    def test_comma_string_and_sequence(self):
        self.assertEqual(parse_whitelist("CAP_CHOWN"), frozenset({"CAP_CHOWN"}))
        self.assertEqual(
            parse_whitelist("CAP_CHOWN, CAP_DAC_OVERRIDE"),
            frozenset({"CAP_CHOWN", "CAP_DAC_OVERRIDE"}),
        )
        self.assertEqual(
            parse_whitelist(["CAP_KILL"]), frozenset({"CAP_KILL"})
        )

    def test_unknown_name_rejected(self):
        with self.assertRaises(CapDropError):
            parse_whitelist("CAP_CHOWN,CAP_NOPE")
        with self.assertRaises(CapDropError):
            parse_whitelist(["chown"])  # must be the full CAP_* name

    def test_wrong_type_rejected(self):
        with self.assertRaises(CapDropError):
            parse_whitelist(42)


class ResolveCapdropTests(unittest.TestCase):
    def test_defaults_are_deny_all(self):
        self.assertEqual(resolve_capdrop(None, None), ())

    def test_service_off_disables_and_ignores_payload(self):
        self.assertIsNone(resolve_capdrop(None, "off"))
        self.assertIsNone(resolve_capdrop(["CAP_CHOWN"], "off"))
        self.assertIsNone(resolve_capdrop(None, False))

    def test_payload_cannot_disable(self):
        # tighten-only: a tool call cannot switch the launcher off.
        self.assertEqual(resolve_capdrop("off", None), ())
        self.assertEqual(resolve_capdrop("off", "CAP_CHOWN"), ("CAP_CHOWN",))

    def test_payload_only_narrows(self):
        self.assertEqual(
            resolve_capdrop("CAP_CHOWN,CAP_KILL", "CAP_CHOWN,CAP_KILL,CAP_SETUID"),
            ("CAP_CHOWN", "CAP_KILL"),
        )
        # Intersection with an empty service set stays deny-all.
        self.assertEqual(resolve_capdrop("CAP_CHOWN", None), ())

    def test_service_whitelist_passes_through(self):
        self.assertEqual(
            resolve_capdrop(None, "CAP_DAC_OVERRIDE"), ("CAP_DAC_OVERRIDE",)
        )

    def test_unknown_names_rejected(self):
        with self.assertRaises(CapDropError):
            resolve_capdrop("CAP_NOPE", None)
        with self.assertRaises(CapDropError):
            resolve_capdrop(None, "CAP_NOPE")


class LoaderArgvTests(unittest.TestCase):
    def test_shape(self):
        argv = capdrop_loader_argv(["true"], [], fd=7)
        self.assertEqual(argv[0], "python3")
        self.assertEqual(argv[1], "-c")
        self.assertEqual(argv[-1], "true")
        config = json.loads(
            __import__("base64").b64decode(argv[3]).decode("utf-8")
        )
        self.assertEqual(config, {"whitelist": [], "fd": 7})

    def test_names_and_policy_resolve_to_numbers(self):
        argv = capdrop_loader_argv(["true"], ["CAP_CHOWN", "CAP_SYS_ADMIN"], fd=3)
        config = json.loads(
            __import__("base64").b64decode(argv[3]).decode("utf-8")
        )
        self.assertEqual(config["whitelist"], [0, 21])
        argv2 = capdrop_loader_argv(["true"], CapDropPolicy(frozenset({"CAP_KILL"})), fd=3)
        config2 = json.loads(
            __import__("base64").b64decode(argv2[3]).decode("utf-8")
        )
        self.assertEqual(config2["whitelist"], [5])

    def test_bad_entries_rejected(self):
        with self.assertRaises(CapDropError):
            capdrop_loader_argv(["true"], ["CAP_NOPE"], fd=3)
        with self.assertRaises(CapDropError):
            capdrop_loader_argv(["true"], [41], fd=3)


class BwrapCapabilityArgsTests(unittest.TestCase):
    def test_deny_all(self):
        self.assertEqual(bwrap_capability_args([]), ["--cap-drop", "ALL"])

    def test_whitelist_adds_survive_the_drop(self):
        # bwrap(1): --cap-add/--cap-drop are processed in command-line order.
        args = bwrap_capability_args(["CAP_CHOWN", "CAP_DAC_OVERRIDE"])
        self.assertEqual(
            args,
            ["--cap-drop", "ALL", "--cap-add", "CAP_CHOWN", "--cap-add", "CAP_DAC_OVERRIDE"],
        )

    def test_unknown_name_rejected(self):
        with self.assertRaises(CapDropError):
            bwrap_capability_args(["CAP_NOPE"])


class SummarizeReportTests(unittest.TestCase):
    def test_summary_line(self):
        report = {
            "whitelist": [],
            "after": {
                "CapInh": "0000000000000000",
                "CapPrm": "0000000000000000",
                "CapEff": "0000000000000000",
                "CapBnd": "0000000000000000",
                "CapAmb": "0000000000000000",
            },
            "ops": [
                {"op": "ambient_clear", "ok": True, "detail": ""},
                {"op": "bounding_drop", "ok": True, "detail": "dropped=0,1,2"},
                {"op": "securebits", "ok": True, "detail": "0xcb locked"},
                {"op": "capset", "ok": True, "detail": "eff/prm/inh=00000000/00000000"},
            ],
        }
        line = summarize_report(report)
        self.assertIn("deny-all", line)
        self.assertIn("CapEff", line)
        self.assertIn("locked", line)


@unittest.skipUnless(LINUX, "capset/prctl are Linux-only")
class LiveCapdropTests(unittest.TestCase):
    """Real kernel behavior: the loader actually drops capabilities."""

    def test_deny_all_zeroes_all_five_sets(self):
        proc, report = _run_loader([], _READ_SETS_PY)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        child = json.loads(proc.stdout)
        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertEqual(child[field], "0000000000000000", field)
        self.assertIsNotNone(report)
        self.assertEqual(report["whitelist"], [])
        self.assertTrue(report["after"]["CapEff"] == "0000000000000000")
        self.assertEqual(report["errors"], [])

    def test_whitelist_never_fabricates_privilege(self):
        # Whitelist CAP_CHOWN (bit 0): the child may keep bit 0 in the
        # bounding set, but must never gain a bit outside the whitelist.
        # (After exec of a binary without file capabilities the kernel
        # clears permitted/effective per the execve transformation rules —
        # the guarantee that matters is "no bit outside the whitelist".)
        proc, report = _run_loader(["CAP_CHOWN"], _READ_SETS_PY)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        child = json.loads(proc.stdout)
        for field, value in child.items():
            self.assertEqual(int(value, 16) & ~0x1, 0, field)

    def test_escalation_attempt_gets_eperm(self):
        # After deny-all, re-raising CAP_SYS_ADMIN via capset must EPERM:
        # the drop is irreversible from inside.
        proc, _report = _run_loader([], _ESCALATE_PY)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        probe = json.loads(proc.stdout)
        self.assertNotEqual(probe["rc"], 0)
        self.assertEqual(probe["errno"], 1)  # EPERM

    def test_whitelist_of_unheld_capability_fails_closed(self):
        # CAP_SYS_PTRACE (bit 19) is not in this process's permitted set, so
        # the whitelist cannot be honored: 126 and the target never runs.
        proc, _report = _run_loader(["CAP_SYS_PTRACE"], _READ_SETS_PY)
        self.assertEqual(proc.returncode, 126)
        self.assertEqual(proc.stdout, "")
        self.assertIn("capdrop failed", proc.stderr)

    def test_read_capability_sets_shape(self):
        sets = read_capability_sets()
        self.assertEqual(
            set(sets),
            {"inheritable", "permitted", "effective", "bounding", "ambient"},
        )
        for value in sets.values():
            self.assertIsInstance(value, int)
            self.assertGreaterEqual(value, 0)


if __name__ == "__main__":
    unittest.main()
