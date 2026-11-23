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
        """The NEW_TESTS threshold must be 9 for a slice WITH a taskbook."""
        if not ACCEPT.is_file():
            self.skipTest(f"live referee not installed: {ACCEPT}")
        text = ACCEPT.read_text(encoding="utf-8")
        # The threshold is now COMPUTED (see
        # NewTestsThresholdTaskbookLessTests), so read it off the
        # taskbook branch.
        m = re.search(
            r'if \[ -s "\$TASKBOOK" \]; then\s*\n\s*NTEST_THRESHOLD=(\d+)', text
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

    def test_the_judge_compares_against_the_computed_threshold(self):
        """The verdict must use $NTEST_THRESHOLD, not a literal number."""
        # The referee is the COORDINATOR's tool: it lives outside the
        # repository, so a CI runner does not have it.  The sibling test
        # above already skips when it is absent -- this one did not, and
        # read the file unconditionally.  Measured 2026-11-22: on a
        # simulated runner this test FAILED with FileNotFoundError,
        # while its sibling skipped.  An absent referee is a SKIP.
        if not ACCEPT.is_file():
            self.skipTest(f"live referee not installed: {ACCEPT}")
        text = ACCEPT.read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r'\$NTEST"\s+-ge\s+"?\$NTEST_THRESHOLD"?\s*\]',
            "the NEW_TESTS verdict must compare against $NTEST_THRESHOLD",
        )


class NewTestsThresholdTaskbookLessTests(unittest.TestCase):
    """The threshold that applies is the one the slice was PROMISED.

    MEASURED (2026-11-16): seven slices have no taskbook file at all --
    `runtime-registration`, `slice1`..`slice6`.  They were launched before
    the taskbook mechanism existed (the template's "> = 9 new test methods"
    clause was added on 2026-11-14 08:22; those slices ran on 2026-11-12).

    Holding them to a contract they were never given is the same false FAIL
    that the CANARY check had for the 8 taskbooks written before the canary
    mechanism existed -- and the same reasoning applies: "no comparison was
    possible" is not "the slice failed".

    The rule the referee must implement:

      * a slice WITH a taskbook    -> threshold 9 (the taskbook's promise)
      * a slice WITHOUT a taskbook -> threshold 1 (the pre-taskbook rule,
                                      and the only rule that existed when
                                      those slices ran)

    Measured distinct new test methods for the seven:

        runtime-registration  37    slice1   7    slice2   2
        slice3                3    slice4   0    slice5  18
        slice6               13

    So `slice4` (0 new methods) still fails even under the pre-taskbook rule,
    while slice1/2/3 pass again.
    """

    @classmethod
    def setUpClass(cls):
        if not ACCEPT.is_file():
            raise unittest.SkipTest(f"live referee not installed: {ACCEPT}")
        cls.text = ACCEPT.read_text(encoding="utf-8")

    def test_the_threshold_depends_on_whether_a_taskbook_exists(self):
        """The judge must pick the threshold from the taskbook's existence."""
        self.assertRegex(
            self.text,
            r"NTEST_THRESHOLD=",
            "the referee must compute a threshold rather than hard-coding 9",
        )
        self.assertRegex(
            self.text,
            r'if \[ -s "\$TASKBOOK" \]',
            "the threshold must be selected by whether the taskbook exists",
        )

    def test_a_slice_with_a_taskbook_gets_the_threshold_of_nine(self):
        """The taskbook contract is >= 9."""
        m = re.search(
            r'if \[ -s "\$TASKBOOK" \]; then\s*\n\s*NTEST_THRESHOLD=(\d+)', self.text
        )
        self.assertIsNotNone(
            m,
            "could not find the taskbook branch of the threshold selection",
        )
        self.assertEqual(9, int(m.group(1)))

    def test_a_slice_without_a_taskbook_gets_the_threshold_of_one(self):
        """The pre-taskbook rule was >= 1."""
        m = re.search(
            r"else\s*\n\s*NTEST_THRESHOLD=(\d+)", self.text
        )
        self.assertIsNotNone(
            m,
            "could not find the no-taskbook branch of the threshold selection",
        )
        self.assertEqual(1, int(m.group(1)))

    def test_the_verdict_uses_the_computed_threshold(self):
        """The NEW_TESTS verdict must compare against the computed threshold."""
        self.assertRegex(
            self.text,
            r'\$NTEST"\s+-ge\s+"?\$NTEST_THRESHOLD"?\s*\]',
            "the NEW_TESTS verdict must use $NTEST_THRESHOLD, not a literal",
        )


if __name__ == "__main__":
    unittest.main()
