"""Static tests for the low-privilege security-contract GitHub workflow.

These tests intentionally do not run scanners, the future native lab, signing, or
any other branch's tests.  They only inspect the workflow text and shell script.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "security-contract-tests.yml"
CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON_SHA = "a26af69be951a213d495a4c3e4e4022e16d87065"


class SecurityContractWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def _on_block(self) -> str:
        match = re.search(r"^on:\s*$", self.text, flags=re.MULTILINE)
        self.assertIsNotNone(match, "workflow must declare top-level on triggers")
        assert match is not None
        following = self.text[match.end():]
        next_top_level = re.search(r"^\S[^\n]*:\s*$", following, flags=re.MULTILINE)
        return following[:next_top_level.start()] if next_top_level else following

    def _permission_blocks(self) -> list[list[str]]:
        lines = self.text.splitlines()
        blocks: list[list[str]] = []
        for index, line in enumerate(lines):
            match = re.fullmatch(r"(?P<indent>\s*)permissions:\s*", line)
            if not match:
                continue
            base_indent = len(match.group("indent"))
            block: list[str] = []
            for candidate in lines[index + 1:]:
                if not candidate.strip() or candidate.lstrip().startswith("#"):
                    continue
                indent = len(candidate) - len(candidate.lstrip())
                if indent <= base_indent:
                    break
                block.append(candidate.strip())
            blocks.append(block)
        return blocks

    def test_required_events_have_no_path_filters(self) -> None:
        trigger_block = self._on_block()
        for event in ("pull_request", "push", "merge_group"):
            self.assertRegex(trigger_block, rf"(?m)^  {event}:\s*$")
        self.assertNotRegex(trigger_block, r"(?m)^\s*paths(?:-ignore)?:")

    def test_permissions_are_contents_read_only_at_every_scope(self) -> None:
        blocks = self._permission_blocks()
        self.assertGreaterEqual(len(blocks), 2, "top-level and job-level permissions are required")
        self.assertEqual(blocks, [["contents: read"], ["contents: read"]])
        self.assertNotIn("id-token", self.text)
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_", self.text)

    def test_only_the_two_pinned_external_actions_are_used(self) -> None:
        actions = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.text)
        self.assertEqual(
            actions,
            [
                f"actions/checkout@{CHECKOUT_SHA}",
                f"actions/setup-python@{SETUP_PYTHON_SHA}",
            ],
        )

    def test_python_and_pytest_versions_are_explicit(self) -> None:
        self.assertRegex(self.text, r'(?m)^\s*python-version:\s*["\']3\.12["\']\s*$')
        self.assertIn('"pytest==9.1.1"', self.text)
        self.assertIn("security/requirements.txt", self.text)

    def test_only_fixed_local_tests_and_lab_entrypoint_are_selected(self) -> None:
        self.assertIn('Path("security/tests")', self.text)
        self.assertIn('Path("security/native_tests")', self.text)
        self.assertIn('native_tests.rglob("test_*.py")', self.text)
        self.assertIn("lab='security/run-native-security-lab.py'", self.text)
        self.assertIn('if [ -f "$lab" ]; then', self.text)
        self.assertIn('python "$lab"', self.text)
        self.assertNotIn("continue-on-error", self.text)
        for forbidden in ("curl ", "wget ", "http://", "https://", "docker ", "podman "):
            self.assertNotIn(forbidden, self.text)

    def test_workflow_has_no_signing_or_publication_step(self) -> None:
        lowered = self.text.lower()
        for forbidden in ("sigstore", "cosign", "gpg", "attest", "publish", "deploy", "release", "upload-artifact"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
