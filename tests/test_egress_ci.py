"""Egress must have its own fail-closed Linux CI gate, not just a Makefile entry."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EgressCITests(unittest.TestCase):
    def test_egress_suite_has_an_independent_linux_job(self):
        workflow = (ROOT / '.github/workflows/test.yml').read_text()
        match = re.search(r'^  egress-sidecar:\n(.*?)(?=^  [\w-]+:\n|\Z)', workflow, re.M | re.S)
        self.assertIsNotNone(match, 'egress has no independent CI job')
        job = match.group(1)
        self.assertIn('runs-on: ubuntu-latest', job)
        self.assertIn('timeout-minutes: 5', job)
        self.assertIn('working-directory: components/northstar-egress-sidecar', job)
        self.assertIn('python -m py_compile *.py tests/test_*.py', job)
        self.assertIn("python -m unittest discover -s tests -p 'test_*.py' -v", job)
        self.assertNotRegex(job, r'continue-on-error|\|\|\s*(?:true|:)|--skip|--exclude')
        self.assertIn('uses: actions/checkout@v4', job)
        self.assertIn('uses: actions/setup-python@v5', job)


if __name__ == '__main__':
    unittest.main()
