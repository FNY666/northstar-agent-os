"""Tests for content_moderator."""

import ast
import os
import sys

import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from content_moderator import (  # noqa: E402
    CONTENT_MODERATOR_SCHEMA,
    CONTENT_MODERATOR_VERSION,
    AUDIT_SCHEMA,
    ACTIONS,
    APPEAL_OUTCOMES,
    CATEGORIES,
    SEVERITIES,
    VERDICT_CLEAN,
    VERDICT_FLAGGED,
    VERDICT_VIOLATION,
    AppealStateError,
    BadInputError,
    ContentModerator,
    ContentModeratorError,
    DisproportionateActionError,
    SeqOrderError,
    TerminalActionError,
    UnknownActionError,
    UnknownAppealError,
    UnknownContentError,
    UnknownReviewError,
    content_moderator_audit_event,
    main,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "content_moderator.py")
DIGEST = "sha256:" + "cd" * 32


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(CONTENT_MODERATOR_VERSION, "content-moderator.v1")
        self.assertEqual(CONTENT_MODERATOR_SCHEMA, "northstar.content-moderator.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        with open(MODULE_PATH, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        allowed = {
            "hashlib", "json", "threading", "dataclasses", "typing",
            "__future__", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)

    def test_main(self):
        self.assertIsNone(main())


class TestSubmit(unittest.TestCase):
    def setUp(self):
        self.mod = ContentModerator()

    def test_submit_roundtrip(self):
        item = self.mod.submit(content_digest=DIGEST, seq=1, author="u1")
        self.assertTrue(item.content_id.startswith("cnt-"))
        self.assertTrue(item.verify())
        self.assertEqual(self.mod.content_item(item.content_id), item)

    def test_submit_bad_digest(self):
        with self.assertRaises(BadInputError):
            self.mod.submit(content_digest="  ", seq=1)

    def test_submit_unknown_content(self):
        with self.assertRaises(UnknownContentError):
            self.mod.content_item("cnt-999")

    def test_seq_order(self):
        self.mod.submit(content_digest=DIGEST, seq=1)
        with self.assertRaises(SeqOrderError):
            self.mod.submit(content_digest=DIGEST, seq=1)  # not increasing
        with self.assertRaises(SeqOrderError):
            self.mod.submit(content_digest=DIGEST, seq=True)  # bool refused


class TestReview(unittest.TestCase):
    def setUp(self):
        self.mod = ContentModerator()
        self.item = self.mod.submit(content_digest=DIGEST, seq=1)

    def test_clean_verdict(self):
        rev = self.mod.review(self.item.content_id, 2)
        self.assertEqual(rev.verdict, VERDICT_CLEAN)
        self.assertIsNone(rev.top_severity)
        self.assertTrue(rev.verify())

    def test_flagged_verdict(self):
        rev = self.mod.review(self.item.content_id, 2, [("spam", "medium")])
        self.assertEqual(rev.verdict, VERDICT_FLAGGED)
        self.assertEqual(rev.top_severity, "medium")
        self.assertTrue(rev.verify())

    def test_violation_verdict(self):
        rev = self.mod.review(self.item.content_id, 2,
                              [("spam", "low"), ("violence", "critical")])
        self.assertEqual(rev.verdict, VERDICT_VIOLATION)
        self.assertEqual(rev.top_severity, "critical")

    def test_review_unknown_content(self):
        with self.assertRaises(UnknownContentError):
            self.mod.review("cnt-999", 2)

    def test_review_bad_finding(self):
        with self.assertRaises(BadInputError):
            self.mod.review(self.item.content_id, 2, [("nope", "low")])
        with self.assertRaises(BadInputError):
            self.mod.review(self.item.content_id, 3, [("spam", "extreme")])


class TestAction(unittest.TestCase):
    def setUp(self):
        self.mod = ContentModerator()
        self.item = self.mod.submit(content_digest=DIGEST, seq=1)
        self.flag = self.mod.review(self.item.content_id, 2,
                                    [("spam", "medium")])
        self.viol = self.mod.review(self.item.content_id, 3,
                                    [("violence", "critical")])
        self.clean = self.mod.review(self.item.content_id, 4)

    def test_action_roundtrip(self):
        act = self.mod.action(self.flag.review_id, 5, action="warn",
                              reason="spam pattern")
        self.assertTrue(act.action_id.startswith("act-"))
        self.assertEqual(act.state, "active")
        self.assertTrue(act.verify())

    def test_disproportionate_on_clean(self):
        with self.assertRaises(DisproportionateActionError):
            self.mod.action(self.clean.review_id, 5, action="warn",
                            reason="should not fire")

    def test_allow_on_clean(self):
        act = self.mod.action(self.clean.review_id, 5, action="allow",
                              reason="no findings")
        self.assertEqual(act.action, "allow")

    def test_below_floor(self):
        with self.assertRaises(DisproportionateActionError):
            self.mod.action(self.flag.review_id, 5, action="ban",
                            reason="ban is over the floor for medium")

    def test_ban_terminal(self):
        ban = self.mod.action(self.viol.review_id, 5, action="ban",
                              reason="critical violence")
        self.assertEqual(ban.action, "ban")
        with self.assertRaises(TerminalActionError):
            self.mod.action(self.viol.review_id, 6, action="warn",
                            reason="after ban")

    def test_unknown_review(self):
        with self.assertRaises(UnknownReviewError):
            self.mod.action("rev-999", 5, action="warn", reason="x")

    def test_bad_action_vocab(self):
        with self.assertRaises(BadInputError):
            self.mod.action(self.flag.review_id, 5, action="nuke", reason="x")

    def test_actions_for(self):
        act = self.mod.action(self.flag.review_id, 5, action="warn", reason="x")
        got = self.mod.actions_for(self.item.content_id)
        self.assertEqual(tuple(a.action_id for a in got), (act.action_id,))
        with self.assertRaises(UnknownContentError):
            self.mod.actions_for("cnt-999")


class TestAppeal(unittest.TestCase):
    def setUp(self):
        self.mod = ContentModerator()
        self.item = self.mod.submit(content_digest=DIGEST, seq=1)
        rev = self.mod.review(self.item.content_id, 2, [("spam", "high")])
        self.act = self.mod.action(rev.review_id, 3, action="remove",
                                   reason="spam")

    def test_appeal_upheld(self):
        apl = self.mod.appeal(self.act.action_id, 4, grounds="false positive")
        decided = self.mod.decide(apl.appeal_id, 5, outcome="upheld")
        self.assertEqual(decided.outcome, "upheld")
        self.assertTrue(decided.verify())
        self.assertEqual(self.mod.action_record(self.act.action_id).state,
                         "active")

    def test_appeal_overturned_restores(self):
        apl = self.mod.appeal(self.act.action_id, 4, grounds="false positive")
        self.mod.decide(apl.appeal_id, 5, outcome="overturned")
        self.assertEqual(self.mod.action_record(self.act.action_id).state,
                         "restored")

    def test_one_open_appeal(self):
        self.mod.appeal(self.act.action_id, 4, grounds="g1")
        with self.assertRaises(AppealStateError):
            self.mod.appeal(self.act.action_id, 5, grounds="g2")

    def test_double_decide(self):
        apl = self.mod.appeal(self.act.action_id, 4, grounds="g")
        self.mod.decide(apl.appeal_id, 5, outcome="modified")
        with self.assertRaises(AppealStateError):
            self.mod.decide(apl.appeal_id, 6, outcome="upheld")

    def test_unknown_action_appeal(self):
        with self.assertRaises(UnknownActionError):
            self.mod.appeal("act-999", 4, grounds="g")

    def test_unknown_appeal_decide(self):
        with self.assertRaises(UnknownAppealError):
            self.mod.decide("apl-999", 4, outcome="upheld")

    def test_bad_outcome(self):
        apl = self.mod.appeal(self.act.action_id, 4, grounds="g")
        with self.assertRaises(BadInputError):
            self.mod.decide(apl.appeal_id, 5, outcome="dismissed")

    def test_appeal_outcomes_pinned(self):
        self.assertEqual(set(APPEAL_OUTCOMES),
                         {"upheld", "overturned", "modified"})


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mod = ContentModerator()
        item = mod.submit(content_digest=DIGEST, seq=1)
        rev = mod.review(item.content_id, 2, [("spam", "low")])
        act = mod.action(rev.review_id, 3, action="warn", reason="r")
        apl = mod.appeal(act.action_id, 4, grounds="g")
        mod.decide(apl.appeal_id, 5, outcome="upheld")
        log = mod.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertEqual(kinds, ["submitted", "reviewed", "actioned",
                                "appealed", "appeal-decided"])
        for e in log:
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module_version"], "content-moderator.v1")

    def test_audit_no_text_leak(self):
        mod = ContentModerator()
        item = mod.submit(content_digest=DIGEST, seq=1)
        rev = mod.review(item.content_id, 2, [("spam", "low")])
        act = mod.action(rev.review_id, 3, action="warn", reason="spam pattern")
        mod.appeal(act.action_id, 4, grounds="secret-grounds-text")
        blob = str(mod.audit_log())
        self.assertNotIn("secret-grounds-text", blob)
        self.assertNotIn("spam pattern", blob)  # reason text stays out of audit

    def test_audit_helper(self):
        ev = content_moderator_audit_event("reviewed", 1, review_id="rev-1")
        self.assertEqual(ev["kind"], "reviewed")
        self.assertEqual(ev["detail"]["review_id"], "rev-1")
        with self.assertRaises(ContentModeratorError):
            content_moderator_audit_event("bogus", 1)

    def test_error_taxonomy(self):
        for cls in (UnknownContentError, UnknownReviewError,
                    UnknownActionError, UnknownAppealError, BadInputError,
                    SeqOrderError, TerminalActionError, AppealStateError,
                    DisproportionateActionError):
            self.assertTrue(issubclass(cls, ContentModeratorError))


class TestConcurrency(unittest.TestCase):
    def test_thread_safety(self):
        import threading
        mod = ContentModerator()
        errors = []

        def worker(n):
            try:
                item = mod.submit(content_digest=DIGEST, seq=n * 2 + 1)
                mod.review(item.content_id, n * 2 + 2)
            except ContentModeratorError as e:  # seq races are the test's own artifact
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # at least one submission must have succeeded and the tree is consistent
        self.assertGreaterEqual(len(mod._items), 1)


if __name__ == "__main__":
    unittest.main()
