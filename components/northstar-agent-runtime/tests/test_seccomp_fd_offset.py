"""R2525: the seccomp filter handed to ``bwrap --seccomp FD`` must be readable from byte 0.

The BPF program is written to a temp file and the *file descriptor* is inherited
by bwrap. bwrap reads from the descriptor's current offset, so an un-rewound
descriptor yields zero bytes and bwrap exits 1 ("Unable to set up system call
filtering as requested: prctl(PR_SET_SECCOMP) reported EINVAL").

Observed on a real aarch64 Linux host (2026-10-09): offset==EOF -> exit 1,
after seek(0) -> exit 0. This test does not need bwrap: it intercepts the point
where the descriptor is handed over and checks the offset and the bytes.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401 — runtime root on sys.path

from tools import os_sandbox
from tools.os_sandbox import SandboxCapabilities, SandboxRequest, SandboxResult, run_sandboxed
from tools.seccomp import build_default_filter


def _caps() -> SandboxCapabilities:
    return SandboxCapabilities(
        bwrap_path="/usr/bin/bwrap",
        bwrap_usable=True,
        bwrap_detail="fake",
        bwrap_cap_drop=False,
        process_available=True,
        preferred="bwrap",
    )


class SeccompDescriptorOffsetTests(unittest.TestCase):
    def test_seccomp_fd_is_rewound_and_complete_when_bwrap_is_launched(self) -> None:
        seen: dict[str, object] = {}

        def fake_run_popen(argv, *, pass_fds=(), **kwargs):
            # bwrap inherits these descriptors and reads from their *current* offset.
            fds = tuple(pass_fds)
            seen["fds"] = fds
            if fds:
                fd = fds[0]
                seen["offset"] = os.lseek(fd, 0, os.SEEK_CUR)
                size = os.fstat(fd).st_size
                os.lseek(fd, 0, os.SEEK_SET)
                seen["bytes_from_zero"] = os.read(fd, size + 1)
                os.lseek(fd, seen["offset"], os.SEEK_SET)  # leave it as found
            return SandboxResult(
                argv=tuple(argv), backend="bwrap", isolation="os", exit_code=0,
                timed_out=False, stdout="", stderr="", duration_ms=1,
            )

        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(os_sandbox, "_run_popen", fake_run_popen):
            request = SandboxRequest(
                argv=("true",), cwd=Path(root), workspace=Path(root), timeout_ms=5_000
            )
            run_sandboxed(request, backend="bwrap", capabilities=_caps())

        self.assertTrue(seen.get("fds"), "no seccomp descriptor was passed to bwrap")
        self.assertEqual(
            seen["offset"], 0,
            "seccomp fd is not rewound: bwrap would read 0 bytes and refuse to start",
        )
        self.assertEqual(seen["bytes_from_zero"], build_default_filter())


if __name__ == "__main__":
    unittest.main()
