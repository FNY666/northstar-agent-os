"""OS sandbox backends and the governed Shell tool (P1).

The process backend is what every host can exercise offline. bwrap is probed
and, when usable, given one happy-path run — never required for the suite to
pass. Explicit ``bwrap`` without a usable binary must hard-error (no quiet
downgrade): that is the lie this surface exists to refuse.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import support  # noqa: F401 — puts the runtime root on sys.path
from support import RuntimeTestCase

from permissions import PermissionConfig, PermissionEngine
from tools import ToolContext, ToolSandbox, ToolResult, build_default_registry
from tools.os_sandbox import (
    SandboxCapabilities,
    SandboxError,
    SandboxRequest,
    SandboxResult,
    _bwrap_argv,
    _minimal_identity_files,
    probe_capabilities,
    reset_capabilities_cache,
    resolve_backend,
    run_sandboxed,
)
from tools.shell import parse_shell_argv, shell_handler


class BwrapArgvSurfaceTests(unittest.TestCase):
    """Pin the bwrap bind surface: any expansion is a deliberate diff.

    bwrap itself is usually absent from CI, so these tests pin the argv
    _bwrap_argv builds rather than running a sandbox.
    """

    def _argv(self, **kwargs):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-argv-"))
        request = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        return _bwrap_argv(request, bwrap_path="/usr/bin/bwrap", **kwargs)

    def _ro_bind_sources(self, argv):
        return [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]

    def test_ro_binds_are_minimal_and_pinned(self):
        sources = self._ro_bind_sources(self._argv())
        expected = [p for p in ("/usr", "/bin", "/lib", "/lib64", "/sbin") if os.path.exists(p)]
        # The five system roots come first, in that order.  After them come
        # ONLY the interpreter's own directory and the virtualenv prefix
        # root -- and only when they are not already covered by a system
        # root.  Any other addition is a deliberate diff and must show up
        # here.
        from tools.sandbox import _virtualenv_roots

        self.assertEqual(sources[: len(expected)], expected)
        allowed = {os.path.dirname(os.path.realpath(sys.executable))}
        allowed.update(_virtualenv_roots())
        for extra in sources[len(expected) :]:
            self.assertIn(
                extra,
                allowed,
                f"unexpected extra ro-bind {extra!r}; the bind surface must stay pinned",
            )

    def test_workspace_governance_is_read_only_and_temp_is_ephemeral(self):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-governance-"))
        northstar = root / ".northstar"
        tmpdir = northstar / "tmp"
        tmpdir.mkdir(parents=True)
        (northstar / "config.toml").write_text("[policy]\n", encoding="utf-8")
        request = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        argv = _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")
        ro_bind = argv.index("--ro-bind", argv.index(str(root)))
        self.assertEqual(argv[ro_bind + 1 : ro_bind + 3], [str(northstar), str(northstar)])
        tmp_mount = argv.index("--tmpfs", argv.index(str(northstar)))
        self.assertEqual(argv[tmp_mount + 1], str(tmpdir))
        self.assertLess(ro_bind, tmp_mount)

    def test_bwrap_refuses_symlinked_governance_directory(self):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-governance-link-"))
        target = Path(tempfile.mkdtemp(prefix="nsar-bwrap-governance-target-"))
        (root / ".northstar").symlink_to(target, target_is_directory=True)
        request = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        with self.assertRaisesRegex(SandboxError, "workspace .northstar is a symlink"):
            _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")

    def test_bwrap_pledge_without_tmppath_gets_no_writable_temp_mount(self):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-no-tmp-"))
        (root / ".northstar" / "tmp").mkdir(parents=True)
        request = SandboxRequest(
            argv=("true",), cwd=root, workspace=root,
            pledges=("proc", "exec", "rpath"),
        )
        argv = _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")
        self.assertIn("--dir", argv)
        self.assertNotIn("/tmp", [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--tmpfs"])
        self.assertNotIn(str(root / ".northstar" / "tmp"), argv)

    def test_host_identity_and_dns_files_are_never_ro_bound(self):
        argv = self._argv()
        for i, arg in enumerate(argv):
            if arg == "--ro-bind":
                src, dest = argv[i + 1], argv[i + 2]
                self.assertNotIn(dest, ("/etc/passwd", "/etc/group"),
                                 f"real host identity must not be bound (src={src})")
                self.assertNotIn(src, ("/etc/resolv.conf", "/etc/ssl", "/etc/passwd", "/etc/group"),
                                 "host dns/tls/identity files must not be bound")

    def test_synthetic_identity_is_bound_when_paths_given(self):
        argv = self._argv(passwd_path="/tmp/pw", group_path="/tmp/gr")
        self.assertIn("/etc/passwd", argv)
        self.assertIn("/etc/group", argv)
        idx = argv.index("/etc/passwd")
        self.assertEqual(argv[idx - 2:idx + 1], ["--ro-bind", "/tmp/pw", "/etc/passwd"])
        idx = argv.index("/etc/group")
        self.assertEqual(argv[idx - 2:idx + 1], ["--ro-bind", "/tmp/gr", "/etc/group"])

    def test_namespace_and_lifecycle_flags_are_pinned(self):
        argv = self._argv()
        for flag in ("--die-with-parent", "--new-session", "--unshare-pid",
                     "--unshare-net", "--unshare-ipc", "--unshare-uts"):
            self.assertIn(flag, argv)
        # The workspace stays the only writable bind.
        self.assertEqual(argv.count("--bind"), 1)

    def test_minimal_identity_files_expose_only_the_current_user(self):
        import pwd

        passwd, group = _minimal_identity_files()
        self.assertEqual(passwd.count("\n"), 1, "exactly one passwd entry")
        self.assertEqual(group.count("\n"), 1, "exactly one group entry")
        uid, gid = os.getuid(), os.getgid()
        self.assertIn(f":{uid}:{gid}:", passwd)
        self.assertIn(f":{gid}:", group)
        try:
            own_name = pwd.getpwuid(uid).pw_name
        except KeyError:
            own_name = None
        for entry in pwd.getpwall():
            if own_name is not None and entry.pw_name == own_name:
                continue
            self.assertNotIn(f"\n{entry.pw_name}:", "\n" + passwd,
                             f"other host user {entry.pw_name!r} must stay invisible")


class OsSandboxProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_capabilities_cache()

    def tearDown(self) -> None:
        reset_capabilities_cache()

    def test_probe_returns_a_closed_shape(self):
        caps = probe_capabilities(force=True)
        self.assertIn(caps.preferred, ("bwrap", "process"))
        self.assertTrue(caps.process_available)
        data = caps.as_dict()
        self.assertIn(data["isolation"], ("os", "process"))
        self.assertEqual(bool(caps.bwrap_usable), data["bwrap_usable"])

    def test_auto_picks_process_when_bwrap_is_unusable(self):
        caps = probe_capabilities(force=True)
        if caps.bwrap_usable:
            self.skipTest("host has a usable bwrap; cannot assert the process fallback here")
        self.assertEqual(resolve_backend("auto", capabilities=caps), "process")

    def test_explicit_bwrap_refuses_when_unusable(self):
        caps = probe_capabilities(force=True)
        if caps.bwrap_usable:
            self.skipTest("host has usable bwrap; hard-error path needs an unusable probe")
        with self.assertRaises(SandboxError) as caught:
            resolve_backend("bwrap", capabilities=caps)
        message = str(caught.exception).lower()
        self.assertIn("bwrap", message)
        self.assertNotIn("falling back", message)
        self.assertNotIn("downgrade", message)

    def test_unknown_backend_is_a_configuration_error(self):
        with self.assertRaises(SandboxError):
            resolve_backend("firejail")

    def test_bwrap_feature_capabilities_require_successful_child_probes(self):
        from tools import os_sandbox

        ok = subprocess.CompletedProcess([], 0, "", "")
        failed = subprocess.CompletedProcess([], 1, "", "kernel rejected filter")
        with patch.object(os_sandbox.subprocess, "run", return_value=ok), patch.object(
            os_sandbox, "_probe_bwrap_feature", side_effect=[ok, failed]
        ) as feature_probe:
            caps = probe_capabilities(force=True, bwrap_bin="/fake/bwrap")
        self.assertTrue(caps.bwrap_usable)
        self.assertTrue(caps.bwrap_cap_drop)
        self.assertFalse(caps.bwrap_seccomp)
        self.assertIn("kernel rejected filter", caps.bwrap_seccomp_detail)
        self.assertEqual(feature_probe.call_count, 2)

    def test_bwrap_capdrop_refuses_before_spawn_when_live_probe_failed(self):
        from tools import os_sandbox

        caps = SandboxCapabilities(
            bwrap_path="/fake/bwrap", bwrap_usable=True, bwrap_detail="base probe passed",
            bwrap_cap_drop=False, bwrap_seccomp=True, preferred="bwrap",
        )
        with tempfile.TemporaryDirectory() as root, patch.object(os_sandbox, "_run_popen") as launch:
            request = SandboxRequest(argv=("true",), cwd=Path(root), workspace=Path(root))
            with self.assertRaisesRegex(SandboxError, "capability drop.*live --cap-drop probe failed"):
                run_sandboxed(request, backend="bwrap", capabilities=caps)
            launch.assert_not_called()
            self.assertFalse(Path(root, ".northstar").exists())

    def test_bwrap_seccomp_refuses_before_spawn_when_live_probe_failed(self):
        from tools import os_sandbox

        caps = SandboxCapabilities(
            bwrap_path="/fake/bwrap", bwrap_usable=True, bwrap_detail="base probe passed",
            bwrap_cap_drop=True, bwrap_seccomp=False, bwrap_seccomp_detail="filter probe failed",
            preferred="bwrap",
        )
        with tempfile.TemporaryDirectory() as root, patch.object(os_sandbox, "_run_popen") as launch:
            request = SandboxRequest(argv=("true",), cwd=Path(root), workspace=Path(root))
            with self.assertRaisesRegex(SandboxError, "seccomp.*live filter probe failed"):
                run_sandboxed(request, backend="bwrap", capabilities=caps)
            launch.assert_not_called()
            self.assertFalse(Path(root, ".northstar").exists())

    def test_operator_disabled_capdrop_is_explicit_and_can_run(self):
        from tools import os_sandbox

        caps = SandboxCapabilities(
            bwrap_path="/fake/bwrap", bwrap_usable=True, bwrap_detail="base probe passed",
            bwrap_cap_drop=False, bwrap_seccomp=False, preferred="bwrap",
        )
        stub = SandboxResult(("true",), "bwrap", "os", 0, False, "", "", 1)
        with tempfile.TemporaryDirectory() as root, patch.object(os_sandbox, "_run_popen", return_value=stub) as launch:
            request = SandboxRequest(
                argv=("true",), cwd=Path(root), workspace=Path(root),
                capdrop_whitelist=None, seccomp="off",
            )
            result = run_sandboxed(request, backend="bwrap", capabilities=caps)
        self.assertIs(result, stub)
        self.assertIn("disabled by operator", launch.call_args.kwargs["detail"])


class SeccompFilterFdOffsetTests(unittest.TestCase):
    """The BPF filter fd must be rewound before bwrap reads it.

    ``bwrap --seccomp FD`` reads the filter from the fd's CURRENT offset.
    A write leaves that offset at the end of the file, so an unrewound fd
    hands bwrap ZERO bytes: it installs an empty BPF program, and
    ``prctl(PR_SET_SECCOMP)`` rejects that with EINVAL. The symptom is not
    a wrong filter but a refused one, so the whole bwrap backend dies on
    EVERY host -- measured: the probe exits 1 with "reported EINVAL"
    without the rewind and exits 0 with it.
    """

    class FakeProcess:
        """A stand-in for the launched child; never actually spawned."""

        pid = 4242
        returncode = 0

        def communicate(self, *args, **kwargs):
            return ("", "")

        def poll(self):
            return 0

        def wait(self, *args, **kwargs):
            return 0

        def kill(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def setUp(self) -> None:
        super().setUp()
        reset_capabilities_cache()

    def tearDown(self) -> None:
        # The capabilities cache is MODULE-level. A test that probes with a
        # fake bwrap path and does not clear the cache leaves every LATER
        # test in the process pointed at a binary that does not exist --
        # and the failure then shows up in an unrelated module, as a
        # mysterious "Shell failed" instead of as a poisoned cache.
        reset_capabilities_cache()
        super().tearDown()

    def _filter_bytes(self) -> bytes:
        from tools.seccomp import build_default_filter

        return build_default_filter()

    def test_an_unrewritten_filter_fd_hands_bwrap_zero_bytes(self):
        """The defect, reproduced: the fd's offset is at the end."""
        with tempfile.TemporaryFile() as handle:
            handle.write(self._filter_bytes())
            handle.flush()
            fd = handle.fileno()
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), len(self._filter_bytes()))
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(len(os.read(fd, 4096)), len(self._filter_bytes()))

    def test_the_seam_returns_a_fd_that_yields_the_whole_filter(self):
        """The seam must hand over a fd bwrap can read the filter FROM."""
        from tools.os_sandbox import _seccomp_filter_fd
        from tools.seccomp import build_default_filter

        with tempfile.TemporaryFile() as handle:
            fd = _seccomp_filter_fd(handle)
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
            self.assertEqual(len(os.read(fd, 4096)), len(build_default_filter()))

    def test_the_probe_site_hands_over_a_readable_filter(self):
        """The live capability probe must hand bwrap a readable filter."""
        from tools import os_sandbox

        captured: dict[str, int] = {}

        def fake_probe(path, *, cap_drop=False, seccomp_fd=None):
            if seccomp_fd is not None:
                captured["bytes"] = len(os.read(seccomp_fd, 4096))
            return subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as root, patch.object(
            os_sandbox, "_probe_bwrap_feature", side_effect=fake_probe
        ), patch.object(
            os_sandbox.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")
        ):
            probe_capabilities(force=True, bwrap_bin="/fake/bwrap")
        self.assertIn("bytes", captured, "the seccomp probe did not run")
        from tools.seccomp import build_default_filter

        self.assertEqual(captured["bytes"], len(build_default_filter()))

    def test_the_run_site_hands_over_a_readable_filter(self):
        """The bwrap run site must hand bwrap a readable filter."""
        from tools import os_sandbox

        caps = SandboxCapabilities(
            bwrap_path="/fake/bwrap", bwrap_usable=True, bwrap_detail="base probe passed",
            bwrap_cap_drop=True, bwrap_seccomp=True, preferred="bwrap",
        )
        captured: dict[str, int] = {}

        def fake_popen(argv, **kwargs):
            for fd in kwargs.get("pass_fds", ()):  # read the filter as bwrap would
                captured.setdefault("bytes", len(os.read(fd, 4096)))
            return FakeProcess()

        with tempfile.TemporaryDirectory() as root, patch.object(
            os_sandbox, "_run_popen", side_effect=fake_popen
        ):
            request = SandboxRequest(argv=("true",), cwd=Path(root), workspace=Path(root))
            try:
                run_sandboxed(request, backend="bwrap", capabilities=caps)
            except Exception:
                pass
        self.assertIn("bytes", captured, "no filter fd was handed to the launcher")
        from tools.seccomp import build_default_filter

        self.assertEqual(captured["bytes"], len(build_default_filter()))


class RuntimeReadPathTests(unittest.TestCase):
    """Every Landlock rule path must exist on THIS host.

    The loader opens each rule path with ``O_PATH``; a path that does not
    exist raises FileNotFoundError inside the loader and kills every tool
    subprocess. ``/lib64`` is x86-only, so an unfiltered system read-path
    list makes the whole process backend unusable on aarch64 -- measured:
    the loader died with "No such file or directory: '/lib64'".
    """

    def test_the_system_read_paths_are_filtered_to_the_ones_that_exist(self):
        from tools.sandbox import _SYSTEM_READ_PATHS, _runtime_read_paths

        runtime = _runtime_read_paths()
        for path in runtime:
            self.assertTrue(os.path.isdir(path), f"rule path does not exist: {path!r}")
        for path in _SYSTEM_READ_PATHS:
            if os.path.isdir(path):
                self.assertIn(path, runtime)

    def test_a_system_path_that_does_not_exist_is_dropped(self):
        from tools import sandbox

        original = sandbox._SYSTEM_READ_PATHS
        try:
            sandbox._SYSTEM_READ_PATHS = (*original, "/nonexistent-northstar-probe")
            runtime = sandbox._runtime_read_paths()
            self.assertNotIn("/nonexistent-northstar-probe", runtime)
            self.assertTrue(all(os.path.isdir(path) for path in runtime))
        finally:
            sandbox._SYSTEM_READ_PATHS = original

    def test_the_loader_can_open_every_rule_path_it_is_given(self):
        """The rule list the loader receives must be openable."""
        from tools.pledge import filesystem_rules
        from tools.sandbox import _runtime_read_paths

        rules = filesystem_rules(
            frozenset({"stdio", "rpath", "wpath", "cpath"}),
            workspace="/tmp",
            tmpdir="/tmp",
        )
        for rule in rules:
            self.assertTrue(
                os.path.isdir(rule.path),
                f"loader would fail to open rule path {rule.path!r}",
            )


class VirtualenvPrefixReadTests(unittest.TestCase):
    """A virtualenv's own files must be readable inside the sandbox.

    ``site.py`` looks for ``pyvenv.cfg`` in the directory ABOVE
    ``sys.executable``'s directory -- that is, at the venv PREFIX ROOT, not
    under ``bin/`` or ``lib/``.  ``_runtime_read_paths()`` only ever added
    ``prefix/bin``, ``prefix/lib`` and ``prefix/lib64``, so the prefix root
    was never granted and the sandboxed interpreter died in
    ``init_import_site`` with
    ``PermissionError: [Errno 13] Permission denied: '/tmp/.../pyvenv.cfg'``.

    Measured: under a venv the child exits 1 with that error; the same
    child exits 0 once the prefix root is readable.
    """

    def test_a_virtualenv_prefix_root_is_readable_inside_the_sandbox(self):
        from tools.sandbox import _runtime_read_paths

        prefix = sys.prefix
        if prefix == sys.base_prefix:
            self.skipTest("not running from a virtualenv")
        self.assertIn(
            prefix,
            _runtime_read_paths(),
            "the venv prefix root must be readable: pyvenv.cfg lives there",
        )

    def test_the_prefix_root_rule_grants_read_without_write(self):
        from tools.pledge import filesystem_rules
        from tools.sandbox import _runtime_read_paths

        prefix = sys.prefix
        if prefix == sys.base_prefix:
            self.skipTest("not running from a virtualenv")
        rules = filesystem_rules(
            frozenset({"stdio", "rpath", "wpath", "cpath"}),
            workspace="/tmp",
            tmpdir="/tmp",
            runtime_roots=_runtime_read_paths(),
        )
        rule = [r for r in rules if r.path == prefix]
        self.assertEqual(len(rule), 1)
        # READ_FILE (0x4) but NOT WRITE_FILE (0x2): the prefix is a runtime
        # root, never a writable one.
        self.assertTrue(rule[0].access & 0x4)
        self.assertFalse(rule[0].access & 0x2)

    def test_the_prefix_root_is_granted_even_when_it_is_also_a_rule_root(self):
        """A prefix that is a system root must not be granted twice."""
        from tools.sandbox import _runtime_read_paths

        runtime = _runtime_read_paths()
        self.assertEqual(len(runtime), len(set(runtime)))


class BwrapVirtualenvBindTests(unittest.TestCase):
    """bwrap must be able to reach a virtualenv interpreter too.

    The bwrap argv bound only the five hardcoded system roots, so a venv
    interpreter was simply absent from the namespace: bwrap failed with
    ``execvp /tmp/.../bin/python: No such file or directory``.
    """

    def _argv(self):
        import tempfile
        from pathlib import Path

        root = Path(tempfile.mkdtemp(prefix="nsar-bwrap-venv-"))
        request = SandboxRequest(argv=("true",), cwd=root, workspace=root)
        return _bwrap_argv(request, bwrap_path="/usr/bin/bwrap")

    def test_the_interpreter_directory_is_reachable_in_the_namespace(self):
        argv = self._argv()
        sources = [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]
        exe_dir = os.path.dirname(os.path.realpath(sys.executable))
        # REACHABLE, not necessarily bound verbatim: a bind of "/usr" already
        # covers "/usr/bin", and repeating it would grow the argv for nothing.
        self.assertTrue(
            any(exe_dir == s or exe_dir.startswith(s.rstrip("/") + "/") for s in sources),
            f"the interpreter's own directory {exe_dir!r} is not reachable; binds={sources!r}",
        )

    def test_a_virtualenv_prefix_root_is_ro_bound(self):
        if sys.prefix == sys.base_prefix:
            self.skipTest("not running from a virtualenv")
        argv = self._argv()
        sources = [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]
        self.assertIn(sys.prefix, sources, "the venv prefix root holds pyvenv.cfg")


class OsSandboxProcessBackendTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.workspace({"marker.txt": "hello-sandbox\n"})

    def _request(self, argv, **kwargs):
        return SandboxRequest(
            argv=tuple(argv),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=kwargs.get("timeout_ms", 5_000),
            max_output_bytes=kwargs.get("max_output_bytes", 8_192),
            cpu_limit_seconds=kwargs.get("cpu_limit_seconds", 5),
            memory_limit_bytes=kwargs.get("memory_limit_bytes", 2 * 1024 * 1024 * 1024),
            file_size_limit_bytes=kwargs.get("file_size_limit_bytes", 1024 * 1024 * 1024),
            env=kwargs.get("env"),
            seccomp=kwargs.get("seccomp", "auto"),
            landlock=kwargs.get("landlock", "auto"),
            capdrop_whitelist=kwargs.get("capdrop_whitelist", ()),
            pledges=kwargs.get("pledges"),
        )

    def test_process_backend_runs_argv_and_labels_isolation(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "print('ns-ok')"]),
            backend="process",
        )
        self.assertEqual(result.backend, "process")
        self.assertEqual(result.isolation, "process")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ns-ok", result.stdout)
        body = result.render()
        self.assertIn("backend=process", body)
        self.assertIn("isolation=process", body)

    def test_process_backend_does_not_resolve_security_loader_from_path(self):
        fake_bin = Path(tempfile.mkdtemp(prefix="nsar-hostile-path-"))
        marker = fake_bin / "python3-ran"
        fake_python = fake_bin / "python3"
        fake_python.write_text(
            f"#!/bin/sh\nprintf compromised > {marker}\nexit 0\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")}):
            result = run_sandboxed(
                self._request([sys.executable, "-c", "print('loader-pinned')"]),
                backend="process",
            )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("loader-pinned", result.stdout)
        self.assertFalse(marker.exists(), "PATH impostor ran before the sandbox controls")

    def test_process_backend_enforces_per_process_file_size_limit(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "open('oversize.bin', 'wb').write(b'x' * (2 * 1024 * 1024))"],
                file_size_limit_bytes=1024 * 1024,
                seccomp="off",
                landlock="off",
                capdrop_whitelist=None,
            ),
            backend="process",
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertLessEqual((self.root / "oversize.bin").stat().st_size, 1024 * 1024)
        self.assertIn("not aggregate quotas", result.detail)

    def test_process_backend_enforces_address_space_limit(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "bytearray(512 * 1024 * 1024)"],
                memory_limit_bytes=128 * 1024 * 1024,
                seccomp="off",
                landlock="off",
                capdrop_whitelist=None,
            ),
            backend="process",
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("address space 134217728 bytes", result.detail)

    def test_process_backend_enforces_cpu_time_limit(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "while True: pass"],
                timeout_ms=5_000,
                cpu_limit_seconds=1,
                seccomp="off",
                landlock="off",
                capdrop_whitelist=None,
            ),
            backend="process",
        )
        self.assertFalse(result.timed_out, "CPU ceiling should fire before the wall-clock timeout")
        self.assertNotEqual(result.exit_code, 0)

    def test_narrow_pledges_fail_closed_without_landlock(self):
        request = self._request(
            [sys.executable, "-c", "print('must-not-run')"],
            pledges=("stdio", "rpath", "proc", "exec"),
        )
        with patch("tools.os_sandbox.landlock_supported", return_value=False):
            with self.assertRaisesRegex(SandboxError, "narrowed Shell pledges require Landlock"):
                run_sandboxed(request, backend="process")

    def test_narrow_pledges_fail_closed_when_landlock_is_off(self):
        request = self._request(
            [sys.executable, "-c", "print('must-not-run')"],
            pledges=("stdio", "rpath", "proc", "exec"),
            landlock="off",
        )
        with self.assertRaisesRegex(SandboxError, "narrowed Shell pledges require Landlock"):
            run_sandboxed(request, backend="process")

    def test_narrow_pledges_fail_closed_when_seccomp_is_off(self):
        request = self._request(
            [sys.executable, "-c", "print('must-not-run')"],
            pledges=("stdio", "rpath", "proc", "exec"),
            seccomp="off",
        )
        with patch("tools.os_sandbox.landlock_supported", return_value=True):
            with self.assertRaisesRegex(SandboxError, "cannot be enforced with seccomp='off'"):
                run_sandboxed(request, backend="process")

    def test_resource_launcher_never_raises_parent_hard_limit(self):
        from tools.resource_limits import MAX_OPEN_FILES, resource_limits_loader_argv

        target = resource_limits_loader_argv(
            [sys.executable, "-c", (
                "import json,resource; print(json.dumps({"
                "'as':resource.getrlimit(resource.RLIMIT_AS),"
                "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE),"
                "'core':resource.getrlimit(resource.RLIMIT_CORE)}))"
            )],
            {
                "cpu_seconds": 10,
                "memory_bytes": 256 * 1024 * 1024,
                "file_size_bytes": 8 * 1024 * 1024,
                "open_files": MAX_OPEN_FILES,
            },
        )
        parent = (
            "import os,resource,sys; "
            "resource.setrlimit(resource.RLIMIT_AS,(64*1024*1024,64*1024*1024)); "
            "os.execv(sys.argv[1],sys.argv[1:])"
        )
        result = subprocess.run(
            [sys.executable, "-c", parent, *target],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["as"], [64 * 1024 * 1024, 64 * 1024 * 1024])
        self.assertLessEqual(observed["nofile"][0], MAX_OPEN_FILES)
        self.assertEqual(observed["core"], [0, 0])

    def test_resource_loader_requires_open_file_limit(self):
        from tools.resource_limits import resource_limits_loader_argv

        with self.assertRaisesRegex(ValueError, "CPU, memory, and file-size"):
            resource_limits_loader_argv(
                [sys.executable, "-c", "pass"],
                {"cpu_seconds": 1, "memory_bytes": 1024, "file_size_bytes": 1024},
            )

    def test_process_backend_enforces_descriptor_and_core_limits(self):
        result = run_sandboxed(
            self._request(
                [
                    sys.executable,
                    "-c",
                    "import json,resource; print(json.dumps({"
                    "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE),"
                    "'core':resource.getrlimit(resource.RLIMIT_CORE)}))",
                ]
            ),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0, result.render())
        observed = json.loads(result.stdout)
        self.assertLessEqual(observed["nofile"][0], 256)
        self.assertEqual(observed["core"], [0, 0])
        self.assertIn("core dumps disabled", result.detail)

    def test_process_backend_terminates_a_command_that_exceeds_output_cap(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "import os; chunk=b'x'*65536\nwhile True: os.write(1, chunk)"],
                timeout_ms=5_000,
                max_output_bytes=1_024,
            ),
            backend="process",
        )
        self.assertFalse(result.timed_out)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout.encode("utf-8")), 1_024)
        self.assertIn("output cap", result.detail)
        self.assertIsNotNone(result.exit_code)

    def test_process_backend_applies_one_output_cap_across_both_streams(self):
        result = run_sandboxed(
            self._request(
                [
                    sys.executable,
                    "-c",
                    "import os, threading; "
                    "a=threading.Thread(target=lambda: os.write(1,b'o'*8192)); "
                    "b=threading.Thread(target=lambda: os.write(2,b'e'*8192)); "
                    "a.start(); b.start(); a.join(); b.join()",
                ],
                timeout_ms=5_000,
                max_output_bytes=1_024,
            ),
            backend="process",
        )
        total = len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
        self.assertTrue(result.truncated)
        self.assertEqual(total, 1_024)

    def test_parent_pipe_error_kills_started_process_group(self):
        pid_file = self.root / "child.pid"
        code = (
            "import os,time; "
            f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); "
            "print('ready', flush=True); time.sleep(30)"
        )
        request = self._request(
            [sys.executable, "-c", code],
            seccomp="off",
            landlock="off",
            capdrop_whitelist=None,
        )
        real_popen = subprocess.Popen
        read_fault = patch(
            "tools.os_sandbox.os.read",
            side_effect=OSError("injected pipe failure"),
        )

        def spawn_then_inject(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            read_fault.start()
            return proc

        try:
            with patch("tools.os_sandbox.subprocess.Popen", side_effect=spawn_then_inject):
                with self.assertRaisesRegex(OSError, "injected pipe failure"):
                    run_sandboxed(request, backend="process")
        finally:
            read_fault.stop()
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_process_backend_kills_background_descendant_after_leader_exit(self):
        if not os.path.isdir("/proc"):
            self.skipTest("requires Linux /proc process state")
        pid_file = self.root / "background-child.pid"
        child = (
            "import os,signal,time,sys; "
            "os.close(0); os.close(1); os.close(2); "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(30)"
        )
        parent = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], "
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "deadline=time.monotonic()+2; "
            "exec(\"while time.monotonic()<deadline and not __import__('os').path.exists(sys.argv[2]): time.sleep(.01)\")"
        )
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", parent, child, str(pid_file)],
                timeout_ms=5_000,
            ),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0, result.render())
        self.assertIn("remaining process-group descendants terminated", result.detail)
        child_pid = int(pid_file.read_text(encoding="ascii"))
        proc_stat = f"/proc/{child_pid}/stat"
        if os.path.exists(proc_stat):
            with open(proc_stat, encoding="ascii") as stream:
                stat_text = stream.read()
            state = stat_text[stat_text.rfind(")") + 2]
            self.assertEqual(state, "Z", "background child must be dead, not running")

    def test_seccomp_prevents_descendants_from_leaving_cleanup_process_group(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("requires Linux seccomp")
        code = (
            "import os\n"
            "for name, call in [('setpgid', lambda: os.setpgid(0, 0)), ('setsid', os.setsid)]:\n"
            "    pid = os.fork()\n"
            "    if pid == 0:\n"
            "        try:\n"
            "            call(); value = 0\n"
            "        except OSError as error:\n"
            "            value = error.errno\n"
            "        os.write(1, (name + ':' + str(value) + '\\n').encode())\n"
            "        os._exit(0)\n"
            "    os.waitpid(pid, 0)\n"
        )
        result = run_sandboxed(
            self._request([sys.executable, "-c", code], timeout_ms=5_000),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0, result.render())
        self.assertEqual(set(result.stdout.splitlines()), {"setpgid:1", "setsid:1"})

    def test_process_backend_pins_cwd_inside_workspace(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "import os; print(os.getcwd())"]),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), str(self.root.resolve()))

    def test_process_backend_scrubs_parent_secrets_from_env(self):
        os.environ["NORTHSTAR_TEST_SECRET"] = "should-not-leak"
        try:
            result = run_sandboxed(
                self._request(
                    [
                        sys.executable,
                        "-c",
                        "import os; print(os.environ.get('NORTHSTAR_TEST_SECRET', 'ABSENT'))",
                    ]
                ),
                backend="process",
            )
        finally:
            os.environ.pop("NORTHSTAR_TEST_SECRET", None)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "ABSENT")

    def test_process_backend_rejects_reserved_env_keys(self):
        with self.assertRaises(SandboxError):
            run_sandboxed(
                self._request([sys.executable, "-c", "print(1)"], env={"PATH": "/evil"}),
                backend="process",
            )

    def test_request_bounds_argv_by_utf8_bytes(self):
        code = "print(" + repr("界" * 12_000) + ")"
        with self.assertRaisesRegex(SandboxError, "argv total size exceeds"):
            run_sandboxed(
                self._request([sys.executable, "-c", code]),
                backend="process",
            )

    def test_request_bounds_total_environment_bytes(self):
        with self.assertRaisesRegex(SandboxError, "env total size exceeds"):
            run_sandboxed(
                self._request(
                    [sys.executable, "-c", "pass"],
                    env={"NORTHSTAR_BIG": "x" * (32 * 1024)},
                ),
                backend="process",
            )

    def test_numeric_request_limits_reject_booleans(self):
        for field, value in (("timeout_ms", True), ("max_output_bytes", False)):
            with self.subTest(field=field), self.assertRaisesRegex(SandboxError, field):
                run_sandboxed(
                    self._request([sys.executable, "-c", "pass"], **{field: value}),
                    backend="process",
                )

    def test_process_backend_rejects_cwd_escape(self):
        outside = self.workspace()
        with self.assertRaises(SandboxError):
            run_sandboxed(
                SandboxRequest(
                    argv=(sys.executable, "-c", "print(1)"),
                    cwd=outside,
                    workspace=self.root,
                ),
                backend="process",
            )

    def test_process_backend_times_out_and_kills_the_group(self):
        result = run_sandboxed(
            self._request(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout_ms=200,
            ),
            backend="process",
        )
        self.assertTrue(result.timed_out)
        self.assertIn("timed_out=true", result.render())

    def test_process_backend_non_zero_exit_is_a_result_not_a_raise(self):
        result = run_sandboxed(
            self._request([sys.executable, "-c", "import sys; sys.exit(7)"]),
            backend="process",
        )
        self.assertEqual(result.exit_code, 7)
        self.assertFalse(result.ok)
        self.assertFalse(result.timed_out)

    def test_process_backend_seccomp_denies_socket_creation(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("seccomp socket enforcement requires Linux")
        if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
            self.skipTest("the seccomp syscall table is not defined for this architecture")
        code = (
            "import socket\n"
            "for name, create in [('socket', socket.socket), "
            "('socketpair', socket.socketpair)]:\n"
            " try:\n  create()\n"
            " except OSError as e: print(name, type(e).__name__, e.errno)\n"
            " else: print(name, 'created')\n"
        )
        result = run_sandboxed(
            self._request([sys.executable, "-c", code], seccomp="on"),
            backend="process",
        )
        self.assertEqual(result.exit_code, 0, result.render())
        self.assertIn("socket PermissionError 1", result.stdout)
        self.assertIn("socketpair PermissionError 1", result.stdout)
        self.assertNotIn(" created", result.stdout)

    def test_network_true_is_refused(self):
        request = SandboxRequest(
            argv=(sys.executable, "-c", "print(1)"),
            cwd=self.root,
            workspace=self.root,
            network=True,
        )
        with self.assertRaises(SandboxError):
            run_sandboxed(request, backend="process")


class OsSandboxBwrapBackendTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        reset_capabilities_cache()
        self.caps = probe_capabilities(force=True)
        self.root = self.workspace()

    def tearDown(self) -> None:
        reset_capabilities_cache()
        super().tearDown()

    def test_bwrap_backend_when_usable(self):
        if not self.caps.bwrap_usable:
            self.skipTest(f"bwrap unusable on this host: {self.caps.bwrap_detail}")
        if not self.caps.bwrap_cap_drop or not self.caps.bwrap_seccomp:
            self.skipTest("default bwrap request needs live capability-drop and seccomp probes")
        request = SandboxRequest(
            argv=("true",),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=5_000,
        )
        result = run_sandboxed(request, backend="bwrap", capabilities=self.caps)
        self.assertEqual(result.backend, "bwrap")
        self.assertEqual(result.isolation, "os")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("backend=bwrap", result.render())
        self.assertIn("isolation=os", result.render())

    def test_bwrap_cannot_persist_changes_to_workspace_governance(self):
        if not self.caps.bwrap_usable:
            self.skipTest(f"bwrap unusable on this host: {self.caps.bwrap_detail}")
        northstar = self.root / ".northstar"
        northstar.mkdir()
        config = northstar / "config.toml"
        config.write_text("original = true\n", encoding="utf-8")
        request = SandboxRequest(
            argv=("sh", "-c", "printf 'changed = true\\n' > .northstar/config.toml"),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=5_000,
        )
        result = run_sandboxed(request, backend="bwrap", capabilities=self.caps)
        self.assertNotEqual(result.exit_code, 0, result.render())
        self.assertEqual(config.read_text(encoding="utf-8"), "original = true\n")

    def test_bwrap_temp_directory_is_ephemeral_and_writable(self):
        if not self.caps.bwrap_usable:
            self.skipTest(f"bwrap unusable on this host: {self.caps.bwrap_detail}")
        request = SandboxRequest(
            argv=("sh", "-c", "touch \"$TMPDIR/probe\""),
            cwd=self.root,
            workspace=self.root,
            timeout_ms=5_000,
        )
        result = run_sandboxed(request, backend="bwrap", capabilities=self.caps)
        self.assertEqual(result.exit_code, 0, result.render())
        self.assertFalse((self.root / ".northstar" / "tmp" / "probe").exists())


class ShellToolTests(RuntimeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = self.workspace()
        self.ctx = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(self.root),
            services={"shell_backend": "process"},
        )

    def test_registry_includes_shell_as_exec_mutating(self):
        registry = build_default_registry()
        self.assertIn("Shell", registry.names())
        spec = registry.get("Shell")
        self.assertEqual(spec.kind, "exec")
        self.assertTrue(spec.is_mutating)
        self.assertFalse(spec.read_only)

    def test_parse_prefers_argv_and_rejects_both(self):
        self.assertEqual(parse_shell_argv({"argv": ["echo", "a"]}), ("echo", "a"))
        with self.assertRaises(SandboxError):
            parse_shell_argv({"argv": ["echo"], "command": "echo x"})
        with self.assertRaises(SandboxError):
            parse_shell_argv({})

    def test_command_becomes_sh_c_inside_sandbox(self):
        argv = parse_shell_argv({"command": "echo hi"})
        self.assertEqual(argv[1], "-c")
        self.assertEqual(argv[2], "echo hi")
        self.assertTrue(argv[0].endswith("sh"))

    def test_shell_handler_runs_and_labels_backend(self):
        result = shell_handler(
            {"argv": [sys.executable, "-c", "print('shell-ok')"]},
            self.ctx,
        )
        self.assertIsInstance(result, ToolResult)
        self.assertFalse(result.is_error)
        self.assertIn("shell-ok", result.content)
        self.assertIn("backend=process", result.content)
        self.assertIn("isolation=process", result.content)
        self.assertEqual(result.data["backend"], "process")

    def test_model_payload_cannot_downgrade_host_selected_shell_backend(self):
        from tools.shell import shell_tool_spec
        from tool_input_schema import ToolInputSchemaError, validate_tool_input

        spec = shell_tool_spec()
        with self.assertRaises(ToolInputSchemaError):
            validate_tool_input({"argv": ["true"], "backend": "process"}, spec.input_schema)

        ctx = ToolContext(
            session_id="test",
            sandbox=ToolSandbox(self.root),
            services={"shell_backend": "bwrap"},
        )
        result = SandboxResult(
            argv=("true",),
            backend="bwrap",
            isolation="os",
            exit_code=0,
            timed_out=False,
            stdout="",
            stderr="",
            duration_ms=1,
        )
        with patch("tools.shell.run_sandboxed", return_value=result) as run:
            shell_handler({"argv": ["true"], "backend": "process"}, ctx)
        self.assertEqual(run.call_args.kwargs["backend"], "bwrap")

    def test_shell_schema_rejects_undeclared_fields_and_accepts_cmd_alias(self):
        from tools.shell import shell_tool_spec
        from tool_input_schema import ToolInputSchemaError, validate_tool_input

        schema = shell_tool_spec().input_schema
        validate_tool_input({"cmd": "printf ok"}, schema)
        for payload in (
            {"command": "printf ok", "network": True},
            {"argv": ["true"], "shell_backend": "process"},
            {"argv": ["true"], "aggregate_resource_scope": "off"},
        ):
            with self.subTest(payload=payload), self.assertRaises(ToolInputSchemaError):
                validate_tool_input(payload, schema)

    def test_shell_handler_non_zero_exit_is_not_is_error(self):
        result = shell_handler(
            {"argv": [sys.executable, "-c", "import sys; sys.exit(3)"]},
            self.ctx,
        )
        self.assertFalse(result.is_error, "non-zero exit is a result the model must read")
        self.assertEqual(result.data["exit_code"], 3)

    def test_shell_handler_timeout_is_is_error(self):
        result = shell_handler(
            {
                "argv": [sys.executable, "-c", "import time; time.sleep(30)"],
                "timeout_ms": 200,
            },
            self.ctx,
        )
        self.assertTrue(result.is_error)
        self.assertTrue(result.data["timed_out"])

    def test_default_permission_mode_denies_shell_without_allow(self):
        engine = PermissionEngine(PermissionConfig(mode="default"))
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertFalse(decision.allowed)

    def test_accept_edits_does_not_cover_shell(self):
        engine = PermissionEngine(PermissionConfig(mode="acceptEdits"))
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertFalse(
            decision.allowed, "acceptEdits is for file edits, not command execution"
        )

    def test_allowed_tools_shell_auto_approves(self):
        engine = PermissionEngine(
            PermissionConfig(mode="default", allowed_tools=("Shell",))
        )
        engine.register_kind("Shell", "exec")
        decision = engine.evaluate(
            "Shell", kind="exec", mutating=True, payload={"argv": ["true"]}
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "allowed_tools")


if __name__ == "__main__":
    unittest.main()
