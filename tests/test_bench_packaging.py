"""The optional installed benchmark must declare its cross-component dependencies."""
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'components/northstar-agent-runtime'

class BenchPackagingTests(unittest.TestCase):
    def test_optional_bench_dependencies_leave_the_core_dependency_free(self):
        config = tomllib.loads((RUNTIME / 'pyproject.toml').read_text())['project']
        self.assertEqual(config['dependencies'], [])
        bench = config['optional-dependencies'].get('bench', [])
        self.assertEqual(set(bench), {'northstar-run-contract', 'northstar-host', 'northstar-durable-run'})

    def test_installed_bench_ci_installs_local_component_dependencies(self):
        workflow = (ROOT / '.github/workflows/test.yml').read_text()
        self.assertIn('python -m pip install --quiet --no-deps ../northstar-run-contract ../northstar-host ../northstar-durable-run', workflow)

if __name__ == '__main__':
    unittest.main()
