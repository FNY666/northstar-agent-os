"""RED test: the NEW_TESTS threshold must be 9, matching the taskbook contract.

The taskbook template (line 104) says "≥9 个新测试方法" (at least 9 new test
methods).  The judge checks >= 1.  Three slices (mutant-evidence-closure,
orphan-adoption, runtime-registration-closure) therefore PASS with 0 new
test methods, which is the exact false-PASS mode this batch is trying to
kill.

This test is written BEFORE the fix and must FAIL first.
"""
import pathlib
import re
import subprocess
import sys
import unittest

ACCEPT = pathlib.Path("/home/muse-newapi/b173-accept.sh")


class NewTestsThresholdTests(unittest.TestCase):
    def test_the_judge_requires_at_least_nine_new_test_methods(self):
        """The NEW_TESTS threshold must be 9, not 1."""
        if not ACCEPT.is_file():
            self.skipTest(f"live referee not installed: {ACCEPT}")
        text = ACCEPT.read_text(encoding="utf-8")
        # find the NEW_TESTS verdict line and read the threshold off it
        m = re.search(
            r'NTEST"\s*-ge\s*(\d+)\s*\]\s*&&\s*check NEW_TESTS PASS',
            text,
        )
        self.assertIsNotNone(
            m,
            "could not find the NEW_TESTS threshold in b173-accept.sh",
        )
        self.assertEqual(
            9,
            int(m.group(1)),
            "the NEW_TESTS threshold is %s, but the taskbook contract "
            "(b173-taskbook-template.md line 104) requires at least 9 new "
            "test methods" % m.group(1),
        )


if __name__ == "__main__":
    unittest.main()
