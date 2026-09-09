"""The guard harness has one job: a mutation must be judged against a *green* baseline.

That is only true if the throwaway copy contains what the runtime's suite imports, which is not
just the runtime: the bridge tests validate against the real sibling components on purpose. This
test runs the copy step for real - it is fast, offline, and writes only into a temp dir - because
"the harness copies the components" is a claim about code, not a claim about a comment.
"""
import sys
import tempfile
import unittest
from pathlib import Path

COMPONENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT))

from tools import verify_invariants as tool  # noqa: E402


class PrepareCopiesTheWholeComponentsTree(unittest.TestCase):
    def test_every_sibling_component_the_suite_imports_travels_to_the_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nsar-prepare-") as tmp:
            runtime = tool.prepare(Path(tmp))
            self.assertTrue((runtime / "cli.py").exists())
            for name in ("northstar-run-contract", "northstar-host", "northstar-durable-run", "northstar-codex-sidecar"):
                self.assertTrue((Path(tmp) / "components" / name).is_dir(), f"{name} missing from the guard copy")
            # The layout is the contract: the tests bootstrap sibling components from
            # `<repo>/components/...`, so a copy that flattened or renamed them would import the
            # *checked-out* tree instead of the mutated one - and a mutation would look harmless.
            self.assertTrue((tool.REPO / "components" / "northstar-agent-runtime").is_dir())
            self.assertEqual((runtime / "components").exists(), False, "the copy must not nest a second tree")

    def test_the_copy_carries_the_real_component_and_not_a_pycache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nsar-prepare-") as tmp:
            runtime = tool.prepare(Path(tmp))
            self.assertTrue((runtime / "tests" / "test_durable_bridge.py").exists())
            self.assertEqual(list(runtime.rglob("__pycache__")), [], "stale bytecode in the copy would mask a mutation")

    def test_a_copy_of_only_the_component_would_not_be_a_green_baseline(self) -> None:
        """The failure this harness used to have, pinned so it cannot come back quietly."""
        with tempfile.TemporaryDirectory(prefix="nsar-prepare-") as tmp:
            lonely = Path(tmp) / "components/northstar-agent-runtime"
            lonely.parent.mkdir(parents=True, exist_ok=True)
            import shutil

            shutil.copytree(COMPONENT, lonely, ignore=shutil.ignore_patterns("__pycache__"))
            code, output = tool.run(lonely, "test_durable_bridge.py")
            self.assertNotEqual(code, 0, "a runtime-only copy must not look like a usable baseline")
            self.assertIn("test_durable_bridge", output)

    def test_one_mutation_end_to_end_turns_its_test_red(self) -> None:
        # The whole point of the harness, run once for real: an anchor that no longer matches would
        # otherwise be reported only in CI, and only after four other mutations had already run.
        title, filename, edits, pattern, _marker = tool.GUARDS[0]
        with tempfile.TemporaryDirectory(prefix="nsar-prepare-") as tmp:
            runtime = tool.prepare(Path(tmp))
            source = runtime / filename
            text = source.read_text(encoding="utf-8")
            for old, new in edits:
                self.assertEqual(text.count(old), 1, f"{title}: anchor not unique in the copy")
                text = text.replace(old, new)
            source.write_text(text, encoding="utf-8")
            code, output = tool.run(runtime, pattern)
            self.assertNotEqual(code, 0, f"{title}: the guard is not covered by {pattern}")
            failing = [line for line in output.splitlines() if line.startswith(("FAIL:", "ERROR:"))]
            self.assertTrue(failing, f"{title}: no named test failure in the output")
            self.assertIn("test_compaction", "\n".join(failing))


if __name__ == "__main__":
    unittest.main()
