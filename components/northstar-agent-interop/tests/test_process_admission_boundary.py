"""Characterise the intentional boundary between research admission and execution."""
import ast
import inspect
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-host"))
sys.path.insert(0, str(COMPONENT_ROOT.parent / "northstar-run-contract"))
sys.path.insert(0, str(COMPONENT_ROOT))

from process_adapter import ProcessAgentAdapter


class ProcessAdmissionBoundaryTests(unittest.TestCase):
    def test_execute_accepts_only_host_owned_execution_inputs(self):
        parameters = inspect.signature(ProcessAgentAdapter.execute).parameters
        self.assertEqual(
            list(parameters),
            [
                "self",
                "handoff_token",
                "context_ref",
                "handoff_secret",
                "current_policy_revision",
                "now",
            ],
        )
        self.assertNotIn("admission", parameters)
        self.assertNotIn("preflight", parameters)
        self.assertNotIn("liveness", parameters)

    def test_process_adapter_does_not_import_research_snapshot_layers(self):
        source = Path(inspect.getfile(ProcessAgentAdapter)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertNotIn("dispatch_admission", imported)
        self.assertNotIn("dispatch_admission_witness", imported)
        self.assertNotIn("evidence_readiness_preflight", imported)
        self.assertNotIn("route_liveness", imported)

    def test_boundary_is_about_execution_authority_not_missing_checks(self):
        source = Path(inspect.getfile(ProcessAgentAdapter)).read_text(encoding="utf-8")
        for required in (
            "verify_handoff_grant",
            "current_policy_revision",
            "_supported_capabilities",
            "_private_workspace",
            "_run_bounded_process",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
