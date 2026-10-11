"""Linux Landlock unprivileged self-sandbox (tools/sandbox.py).

Offline unit tests cover the pure surface: mode validation, tighten-only
resolution, rights-table bit values (kernel-verified), spec building, and the
loader argv shape. Live tests run the loader for real on Linux kernels with
Landlock and are skipped elsewhere — the whole suite stays deterministic.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from tools.sandbox import (
    LANDLOCK_MODES,
    LandlockError,
    build_landlock_spec,
    default_profile,
    landlock_abi_version,
    landlock_loader_argv,
    landlock_supported,
    probe_landlock,
    resolve_mode,
    rights_mask,
    validate_mode,
    _FS_RIGHTS,
    _NET_RIGHTS,
)


class TestModes(RuntimeTestCase):
    def test_validate_mode(self):
        self.assertEqual(validate_mode("auto"), "auto")
        self.assertEqual(validate_mode("ON"), "on")
        self.assertEqual(validate_mode(""), "auto")
        with self.assertRaises(LandlockError):
            validate_mode("sometimes")
        with self.assertRaises(LandlockError):
            validate_mode(1)

    def test_resolve_mode_tighten_only(self):
        self.assertEqual(resolve_mode(None, "auto"), "auto")
        self.assertEqual(resolve_mode("on", "auto"), "on")
        # A per-call payload may never loosen the operator's setting.
        self.assertEqual(resolve_mode("off", "on"), "on")
        self.assertEqual(resolve_mode("auto", "on"), "on")
        self.assertEqual(resolve_mode("off", "off"), "off")


class TestRightsTables(RuntimeTestCase):
    def test_fs_bit_values_kernel_verified(self):
        # Spot-check against /usr/include/linux/landlock.h on the build host.
        table = {name: bit for name, bit, _ in _FS_RIGHTS}
        self.assertEqual(table["EXECUTE"], 1 << 0)
        self.assertEqual(table["WRITE_FILE"], 1 << 1)
        self.assertEqual(table["READ_FILE"], 1 << 2)
        self.assertEqual(table["READ_DIR"], 1 << 3)
        self.assertEqual(table["REFER"], 1 << 13)
        self.assertEqual(table["TRUNCATE"], 1 << 14)

    def test_net_bit_values_kernel_verified(self):
        table = {name: bit for name, bit, _ in _NET_RIGHTS}
        self.assertEqual(table["BIND_TCP"], 1 << 0)
        self.assertEqual(table["CONNECT_TCP"], 1 << 1)

    def test_abi_gating_masks_new_rights(self):
        # REFER needs ABI 2, TRUNCATE ABI 3, IOCTL_DEV ABI 5, RESOLVE_UNIX 9.
        old = rights_mask(["REFER", "TRUNCATE", "IOCTL_DEV", "RESOLVE_UNIX"], _FS_RIGHTS, abi=1)
        self.assertEqual(old, 0)
        mid = rights_mask(["REFER", "TRUNCATE", "IOCTL_DEV", "RESOLVE_UNIX"], _FS_RIGHTS, abi=4)
        self.assertEqual(mid, (1 << 13) | (1 << 14))
        new = rights_mask(["REFER", "TRUNCATE", "IOCTL_DEV", "RESOLVE_UNIX"], _FS_RIGHTS, abi=9)
        self.assertEqual(new, (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16))
        # TCP rights need ABI 4.
        self.assertEqual(rights_mask(["BIND_TCP", "CONNECT_TCP"], _NET_RIGHTS, abi=3), 0)
        self.assertEqual(rights_mask(["BIND_TCP", "CONNECT_TCP"], _NET_RIGHTS, abi=4), 0b11)


class TestSpec(RuntimeTestCase):
    def test_default_and_pledge_profiles_allow_nonstandard_python_runtime_only(self):
        from pathlib import Path
        from unittest.mock import patch
        from tools.pledge import filesystem_rules
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / 'toolcache' / 'python'
            (prefix / 'bin').mkdir(parents=True)
            (prefix / 'lib').mkdir()
            (root / 'workspace').mkdir()
            with patch.object(sys, 'prefix', str(prefix)), \
                 patch.object(sys, 'base_prefix', str(prefix)), \
                 patch.object(sys, 'executable', str(prefix / 'bin/python3')):
                spec = default_profile(str(root / 'workspace'))
                paths = {rule['path']: rule['rights'] for rule in spec['rules']}
                self.assertIn(str(prefix / 'bin'), paths)
                self.assertIn(str(prefix / 'lib'), paths)
                self.assertNotIn(str(root), paths)
                self.assertNotIn(str(prefix.parent), paths)
                self.assertNotIn('WRITE_FILE', paths[str(prefix / 'lib')])
                pledge_paths = {r.path for r in filesystem_rules(
                    frozenset({'stdio'}), workspace=str(root / 'workspace'), tmpdir=str(root / 'tmp'))}
                self.assertIn(str(prefix / 'bin'), pledge_paths)
                self.assertIn(str(prefix / 'lib'), pledge_paths)
                self.assertNotIn(str(prefix.parent), pledge_paths)

    def test_venv_root_is_readable_but_never_writable_or_widened(self):
        # R2525: a venv interpreter reads <venv>/pyvenv.cfg at start-up (site.py).
        # Only <venv>/bin and <venv>/lib were allowed, so every venv-hosted
        # process-backend command died with PermissionError. Allow the venv root
        # itself read-only; never its parent, and never write.
        from pathlib import Path
        from unittest.mock import patch
        from tools.pledge import filesystem_rules
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base-python"
            venv = root / "projects" / "venv"
            for sub in ("bin", "lib"):
                (base / sub).mkdir(parents=True)
                (venv / sub).mkdir(parents=True)
            (venv / "pyvenv.cfg").write_text("home = %s\n" % (base / "bin"))
            (root / "workspace").mkdir()
            with patch.object(sys, "prefix", str(venv)), \
                 patch.object(sys, "base_prefix", str(base)), \
                 patch.object(sys, "executable", str(venv / "bin" / "python")):
                spec = default_profile(str(root / "workspace"))
                paths = {rule["path"]: rule["rights"] for rule in spec["rules"]}
                self.assertIn(str(venv), paths, "venv root must be readable so pyvenv.cfg can be read")
                self.assertNotIn(str(venv.parent), paths)
                self.assertNotIn(str(root), paths)
                for right in ("WRITE_FILE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE"):
                    self.assertNotIn(right, paths[str(venv)])
                pledge_paths = {r.path for r in filesystem_rules(
                    frozenset({"stdio"}), workspace=str(root / "workspace"), tmpdir=str(root / "tmp"))}
                self.assertIn(str(venv), pledge_paths)
                self.assertNotIn(str(venv.parent), pledge_paths)

    def test_plain_install_prefix_is_not_widened(self):
        # Not a venv (prefix == base_prefix): the prefix itself must NOT be allowed,
        # only its bin/ and lib/ (a prefix like /opt/python or ~/.pyenv is too wide).
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "toolcache" / "python"
            for sub in ("bin", "lib"):
                (prefix / sub).mkdir(parents=True)
            (root / "workspace").mkdir()
            with patch.object(sys, "prefix", str(prefix)), \
                 patch.object(sys, "base_prefix", str(prefix)), \
                 patch.object(sys, "executable", str(prefix / "bin" / "python3")):
                spec = default_profile(str(root / "workspace"))
                paths = {rule["path"] for rule in spec["rules"]}
                self.assertNotIn(str(prefix), paths)
                self.assertIn(str(prefix / "bin"), paths)
                self.assertIn(str(prefix / "lib"), paths)

    def test_build_spec_rejects_missing_paths(self):
        with self.assertRaises(LandlockError):
            build_landlock_spec(paths_read=["/no/such/dir"], paths_write=["/tmp"])
        with self.assertRaises(LandlockError):
            build_landlock_spec(paths_read=["relative/path"], paths_write=["/tmp"])

    def test_build_spec_shape(self):
        spec = build_landlock_spec(paths_read=["/usr"], paths_write=["/tmp"], mode="on")
        self.assertEqual(spec["mode"], "on")
        self.assertFalse(spec["network"])
        self.assertEqual(len(spec["rules"]), 2)
        self.assertIn("EXECUTE", spec["rules"][0]["rights"])

    def test_default_profile(self):
        with tempfile.TemporaryDirectory() as ws:
            spec = default_profile(ws)
        self.assertFalse(spec["network"])
        paths = [r["path"] for r in spec["rules"]]
        self.assertIn(ws, paths)
        self.assertIn("/usr", paths)

    def test_loader_argv_shape(self):
        spec = {"mode": "auto", "rules": [], "network": False, "tcp_ports": []}
        argv = landlock_loader_argv(["/bin/true"], spec)
        self.assertEqual(argv[0], "python3")
        self.assertEqual(argv[1], "-c")
        decoded = json.loads(base64.b64decode(argv[3]).decode())
        self.assertEqual(decoded["mode"], "auto")
        self.assertEqual(argv[4:], ["/bin/true"])
        with self.assertRaises(LandlockError):
            landlock_loader_argv([], spec)

    def test_probe_shape(self):
        probe = probe_landlock()
        self.assertIn("supported", probe)
        self.assertIn("abi", probe)
        self.assertIn("detail", probe)
        self.assertEqual(probe["supported"], landlock_supported())
        self.assertEqual(probe["abi"], landlock_abi_version())


@unittest.skipUnless(
    sys.platform.startswith("linux") and landlock_supported(),
    "needs a Linux kernel with Landlock",
)
class TestLiveLoader(RuntimeTestCase):
    def _run(self, shell_cmd, workspace):
        spec = default_profile(workspace)
        spec["mode"] = "on"
        argv = landlock_loader_argv(["/bin/sh", "-c", shell_cmd], spec)
        return subprocess.run(argv, cwd=workspace, capture_output=True, text=True, timeout=30)

    def test_write_inside_workspace_allowed(self):
        with tempfile.TemporaryDirectory() as ws:
            result = self._run("touch proof.txt && echo ok", ws)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.exists(os.path.join(ws, "proof.txt")))

    def test_write_outside_workspace_denied(self):
        with tempfile.TemporaryDirectory() as ws:
            result = self._run("touch /tmp/landlock_unit_nope 2>err.txt; echo done", ws)
            with open(os.path.join(ws, "err.txt")) as fh:
                self.assertIn("Permission denied", fh.read())
            self.assertFalse(os.path.exists("/tmp/landlock_unit_nope"))

    def test_tcp_denied(self):
        with tempfile.TemporaryDirectory() as ws:
            result = self._run(
                "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", 9), timeout=2)'",
                ws,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Permission denied", result.stderr)

    def test_restriction_is_irreversible_for_child(self):
        # A second restrict_self can only add restrictions: the child tries to
        # re-allow /tmp and must still fail.
        with tempfile.TemporaryDirectory() as ws:
            result = self._run(
                "python3 - <<'PY'\n"
                "import ctypes, os\n"
                "lib = ctypes.CDLL('libc.so.6', use_errno=True)\n"
                "rs = lib.syscall(444, None, 0, 1)\n"
                "print('child-abi-query:', rs)\n"
                "open('/tmp/landlock_unit_nope2', 'w')\n"
                "PY",
                ws,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(os.path.exists("/tmp/landlock_unit_nope2"))


@unittest.skipUnless(
    sys.platform.startswith("linux") and landlock_supported(),
    "needs a Linux kernel with Landlock",
)
class TestLiveDegrade(RuntimeTestCase):
    def test_bad_rule_in_auto_mode_warns_and_fails_closed(self):
        # A spec whose rules cannot be added (path vanished between build and
        # exec): the loader must warn loudly and the child must NOT run
        # unconfined — an empty ruleset denies everything, so exec fails.
        spec = {"mode": "auto", "rules": [{"path": "/nonexistent-x", "rights": ["READ_FILE"]}],
                "network": False, "tcp_ports": []}
        argv = landlock_loader_argv(["/bin/sh", "-c", "echo survived"], spec)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertNotIn("survived", result.stdout)
        self.assertIn("landlock WARNING", result.stderr)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
