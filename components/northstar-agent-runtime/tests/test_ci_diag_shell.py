"""Temporary CI diagnostic: what does the process backend actually say?"""
import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase


class CiDiagShellTests(RuntimeTestCase):
    def test_what_the_process_backend_says(self):
        from tools.os_sandbox import SandboxRequest, run_sandboxed

        workspace = self.workspace()
        command = (
            "echo PROC=$(grep -c '^CapEff' /proc/self/status 2>&1); "
            "echo LIST=$(ls /proc/self/status 2>&1); "
            "echo TMP=$( (echo hi > /tmp/northstar_diag.txt && echo writable) 2>&1 ); "
            "echo PY=$(python3 -c 'print(1)' 2>&1); "
            "echo LANDLOCK=$(cat /proc/self/status | grep -i landlock 2>&1)"
        )
        result = run_sandboxed(
            SandboxRequest(argv=["sh", "-c", command], cwd=str(workspace), workspace=str(workspace))
        )
        raise AssertionError(
            "DIAG stdout=%r stderr=%r exit=%r detail=%r" % (
                result.stdout[-2500:], result.stderr[-1500:], result.exit_code, result.detail[-600:],
            )
        )
