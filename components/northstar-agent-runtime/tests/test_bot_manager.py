"""Tests for bot_manager: good/bad bot allow/challenge/block bookkeeping."""

import ast
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import bot_manager
from bot_manager import (
    AlreadyBlockedError,
    BlockedBotError,
    BotManager,
    BotManagerError,
    ChallengeStateError,
    DuplicateBotError,
    SeqOrderError,
    UnknownBlockError,
    UnknownBotError,
    UnknownChallengeError,
    bot_manager_audit_event,
    BOT_MANAGER_SCHEMA,
    BOT_MANAGER_VERSION,
    CATEGORIES,
    CHALLENGE_JAVASCRIPT,
    CHALLENGE_KINDS,
    CHALLENGE_WINDOW_SEQ,
    KIND_ALLOWED,
    KIND_CHALLENGED,
    KIND_REJECTED,
)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(BOT_MANAGER_VERSION, "bot-manager.v1")
        self.assertEqual(BOT_MANAGER_SCHEMA, "northstar.bot-manager.v1")

    def test_category_vocabulary(self):
        self.assertEqual(CATEGORIES, ("good", "unknown", "suspicious", "bad"))

    def test_challenge_kinds(self):
        self.assertEqual(
            CHALLENGE_KINDS, ("managed", "javascript", "interactive")
        )
        self.assertGreater(CHALLENGE_WINDOW_SEQ, 0)

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "bot_manager.py")
        with open(path) as fh:
            tree = ast.parse(fh.read())
        allowed = {
            "__future__", "hashlib", "threading", "dataclasses", "typing",
            "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(
                        alias.name.split(".")[0], allowed, alias.name
                    )
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(
                    (node.module or "").split(".")[0], allowed, node.module
                )


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.manager = BotManager()

    def test_register_roundtrip(self):
        record = self.manager.register_bot("googlebot", "good", 1)
        self.assertTrue(record.verify())
        self.assertEqual(record.bot_id, "googlebot")
        self.assertEqual(record.category, "good")

    def test_register_duplicate_refused(self):
        self.manager.register_bot("googlebot", "good", 1)
        with self.assertRaises(BotManagerError):
            self.manager.register_bot("googlebot", "good", 2)

    def test_register_bad_category(self):
        with self.assertRaises(BotManagerError):
            self.manager.register_bot("x", "evil", 1)

    def test_register_bad_id(self):
        with self.assertRaises(BotManagerError):
            self.manager.register_bot("   ", "good", 1)

    def test_register_unknown_bot_lookup(self):
        with self.assertRaises(UnknownBotError):
            self.manager.bot("nope")


class TestAllow(unittest.TestCase):
    def setUp(self):
        self.manager = BotManager()
        self.manager.register_bot("googlebot", "good", 1)
        self.manager.register_bot("curl", "unknown", 2)
        self.manager.register_bot("scraper-7", "suspicious", 3)
        self.manager.register_bot("stuffing-net", "bad", 4)

    def test_good_allowed(self):
        verdict = self.manager.allow("googlebot", 5)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.reason, "allowlisted-good")
        self.assertTrue(verdict.verify())

    def test_unknown_denied_as_data(self):
        verdict = self.manager.allow("curl", 5)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, "not-allowlisted")
        self.assertTrue(verdict.verify())

    def test_suspicious_denied_as_data(self):
        verdict = self.manager.allow("scraper-7", 5)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, "suspicious")
        self.assertTrue(verdict.verify())

    def test_bad_denied_as_data(self):
        verdict = self.manager.allow("stuffing-net", 5)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, "known-bad")
        self.assertTrue(verdict.verify())

    def test_blocked_raises(self):
        self.manager.block("stuffing-net", 5, "credential stuffing")
        with self.assertRaises(BlockedBotError):
            self.manager.allow("stuffing-net", 6)

    def test_unknown_bot_raises(self):
        with self.assertRaises(UnknownBotError):
            self.manager.allow("nope", 5)

    def test_allow_is_read_seq_not_consumed(self):
        # A read view must not advance the mutation seq: a later mutation
        # with the same+1 seq must still be accepted.
        self.manager.allow("googlebot", 4)  # same seq as last register
        record = self.manager.register_bot("bingbot", "good", 5)
        self.assertTrue(record.verify())


class TestChallenge(unittest.TestCase):
    def setUp(self):
        self.manager = BotManager()
        self.manager.register_bot("scraper-7", "suspicious", 1)
        self.manager.register_bot("googlebot", "good", 2)
        self.manager.register_bot("stuffing-net", "bad", 3)

    def test_challenge_roundtrip(self):
        record = self.manager.challenge("scraper-7", 4, CHALLENGE_JAVASCRIPT)
        self.assertTrue(record.verify())
        self.assertFalse(record.resolved)
        self.assertEqual(record.expires_seq, 4 + CHALLENGE_WINDOW_SEQ)

    def test_challenge_unknown_bot(self):
        with self.assertRaises(UnknownBotError):
            self.manager.challenge("nope", 4)

    def test_challenge_blocked_bot(self):
        self.manager.block("stuffing-net", 4, "credential stuffing")
        with self.assertRaises(BlockedBotError):
            self.manager.challenge("stuffing-net", 5)

    def test_challenge_bad_kind(self):
        with self.assertRaises(BotManagerError):
            self.manager.challenge("scraper-7", 4, "captcha-v9")


class TestSolveChallenge(unittest.TestCase):
    def setUp(self):
        self.manager = BotManager()
        self.manager.register_bot("scraper-7", "suspicious", 1)
        self.manager.register_bot("stuffing-net", "bad", 2)

    def test_solve_pass_lifts_suspicious(self):
        challenge = self.manager.challenge("scraper-7", 3)
        result = self.manager.solve_challenge(challenge.challenge_id, 4, True)
        self.assertTrue(result.passed)
        self.assertFalse(result.expired)
        self.assertEqual(result.category_after, "unknown")
        self.assertTrue(result.verify())
        self.assertEqual(self.manager.bot("scraper-7").category, "unknown")

    def test_solve_fail_keeps_category(self):
        challenge = self.manager.challenge("scraper-7", 3)
        result = self.manager.solve_challenge(challenge.challenge_id, 4, False)
        self.assertFalse(result.passed)
        self.assertEqual(result.category_after, "suspicious")

    def test_solve_pass_never_promotes_bad(self):
        challenge = self.manager.challenge("stuffing-net", 3)
        result = self.manager.solve_challenge(challenge.challenge_id, 4, True)
        self.assertTrue(result.passed)
        self.assertEqual(result.category_after, "bad")

    def test_solve_expired(self):
        challenge = self.manager.challenge("scraper-7", 3)
        result = self.manager.solve_challenge(
            challenge.challenge_id, 3 + CHALLENGE_WINDOW_SEQ + 1, True
        )
        self.assertTrue(result.expired)
        self.assertFalse(result.passed)
        self.assertEqual(result.category_after, "suspicious")

    def test_solve_twice_refused(self):
        challenge = self.manager.challenge("scraper-7", 3)
        self.manager.solve_challenge(challenge.challenge_id, 4, True)
        with self.assertRaises(ChallengeStateError):
            self.manager.solve_challenge(challenge.challenge_id, 5, True)

    def test_solve_unknown_challenge(self):
        with self.assertRaises(BotManagerError):
            self.manager.solve_challenge("ch-999", 3, True)


class TestBlock(unittest.TestCase):
    def setUp(self):
        self.manager = BotManager()
        self.manager.register_bot("stuffing-net", "bad", 1)

    def test_block_unblock_lifecycle(self):
        block = self.manager.block("stuffing-net", 2, "credential stuffing")
        self.assertTrue(block.verify())
        self.assertTrue(self.manager.is_blocked("stuffing-net"))
        unblock = self.manager.unblock("stuffing-net", 3, "ops review")
        self.assertTrue(unblock.verify())
        self.assertFalse(self.manager.is_blocked("stuffing-net"))

    def test_double_block_refused(self):
        self.manager.block("stuffing-net", 2, "r")
        with self.assertRaises(BotManagerError):
            self.manager.block("stuffing-net", 3, "r")

    def test_unblock_without_block(self):
        with self.assertRaises(BotManagerError):
            self.manager.unblock("stuffing-net", 2, "r")


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_refused(self):
        manager = BotManager()
        manager.register_bot("a", "good", 1)
        with self.assertRaises(SeqOrderError):
            manager.register_bot("b", "good", 1)

    def test_bool_seq_refused(self):
        manager = BotManager()
        with self.assertRaises(SeqOrderError):
            manager.register_bot("a", "good", True)

    def test_failed_mutation_consumes_seq(self):
        manager = BotManager()
        with self.assertRaises(BotManagerError):
            manager.register_bot("a", "evil", 1)
        # seq 1 was consumed by the failed mutation, so 2 must work
        record = manager.register_bot("a", "good", 2)
        self.assertTrue(record.verify())


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        manager = BotManager()
        manager.register_bot("googlebot", "good", 1)
        manager.block("googlebot", 2, "drill")
        kinds = [event["event"] for event in manager.audit_log()]
        self.assertIn("bot-manager.bot-registered", kinds)
        self.assertIn("bot-manager.blocked", kinds)
        for event in manager.audit_log():
            self.assertEqual(event["schema_version"], "audit.ndjson/1")

    def test_audit_event_bad_kind(self):
        with self.assertRaises(BotManagerError):
            bot_manager_audit_event("nope", 1)

    def test_rejected_audit_on_duplicate(self):
        manager = BotManager()
        manager.register_bot("a", "good", 1)
        with self.assertRaises(BotManagerError):
            manager.register_bot("a", "good", 2)
        kinds = [event["event"] for event in manager.audit_log()]
        self.assertIn(KIND_REJECTED, kinds)

    def test_main_selfcheck(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "..", "bot_manager.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("bot-manager OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
