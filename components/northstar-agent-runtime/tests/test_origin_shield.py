"""Tests for origin_shield: 17 cases."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from origin_shield import (
    ORIGIN_SHIELD_VERSION,
    ORIGIN_SHIELD_SCHEMA,
    REGIONS,
    TIERS,
    COLLAPSE_REASONS,
    STATE_ACTIVE,
    STATE_COLLAPSED,
    BadCollapseError,
    BadShieldError,
    DuplicateShieldError,
    OriginShield,
    OriginShieldError,
    SeqOrderError,
    TerminalShieldError,
    UnknownShieldError,
    origin_shield_audit_event,
    main,
)


def fresh():
    return OriginShield()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ORIGIN_SHIELD_VERSION, "origin-shield.v1")
        self.assertEqual(ORIGIN_SHIELD_SCHEMA, "northstar.origin-shield.v1")

    def test_pinned_vocabularies(self):
        self.assertEqual(TIERS, ("single-pop", "regional", "global"))
        self.assertIn("us-east", REGIONS)
        self.assertIn("eu-west", REGIONS)
        self.assertIn("ap-northeast", REGIONS)
        for r in COLLAPSE_REASONS:
            self.assertIsInstance(r, str)
        self.assertEqual(len(set(COLLAPSE_REASONS)), len(COLLAPSE_REASONS))

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "origin_shield.py")
        tree = ast.parse(open(path).read())
        allowed = {"hashlib", "threading", "dataclasses", "typing",
                   "__future__", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_self_check(self):
        main()


class TestShield(unittest.TestCase):
    def test_shield_roundtrip_verify(self):
        oz = fresh()
        rec = oz.shield("sh1", "origin.example.com", 1,
                        region="eu-west", tier="regional")
        self.assertTrue(rec.verify())
        self.assertEqual(rec.schema, ORIGIN_SHIELD_SCHEMA)
        self.assertEqual(rec.tier, "regional")
        self.assertEqual(rec.region, "eu-west")
        self.assertEqual(oz.shield_record("sh1"), rec)
        self.assertEqual(oz.status("sh1"), STATE_ACTIVE)

    def test_shield_defaults(self):
        oz = fresh()
        rec = oz.shield("sh1", "origin.example.com", 1)
        self.assertEqual(rec.region, "us-east")
        self.assertEqual(rec.tier, "single-pop")
        self.assertTrue(rec.verify())

    def test_shield_duplicate_refused(self):
        oz = fresh()
        oz.shield("sh1", "a.example.com", 1)
        with self.assertRaises(DuplicateShieldError):
            oz.shield("sh1", "b.example.com", 2)

    def test_shield_bad_region(self):
        oz = fresh()
        with self.assertRaises(BadShieldError):
            oz.shield("sh1", "origin.example.com", 1, region="moon-base")

    def test_shield_bad_tier(self):
        oz = fresh()
        with self.assertRaises(BadShieldError):
            oz.shield("sh1", "origin.example.com", 1, tier="hyper")

    def test_shield_bad_origin_table(self):
        oz = fresh()
        for i, bad in enumerate(["", "  ", "has space.example", "https://x.com",
                                 "a" * 254]):
            with self.assertRaises(OriginShieldError):
                oz.shield(f"bad{i}", bad, i + 1)

    def test_shield_origin_normalized(self):
        oz = fresh()
        rec = oz.shield("sh1", "Origin.Example.COM", 1)
        self.assertEqual(rec.origin, "origin.example.com")


class TestCollapse(unittest.TestCase):
    def test_collapse_roundtrip_verify(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 1)
        col = oz.collapse("sh1", 2, reason="latency")
        self.assertTrue(col.verify())
        self.assertEqual(col.shield_id, "sh1")
        self.assertEqual(col.reason, "latency")
        self.assertEqual(oz.status("sh1"), STATE_COLLAPSED)
        self.assertNotIn("sh1", oz.active_ids())
        self.assertEqual(oz.collapse_of("sh1"), col)

    def test_collapse_terminal(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 1)
        oz.collapse("sh1", 2)
        with self.assertRaises(TerminalShieldError):
            oz.collapse("sh1", 3)

    def test_collapse_unknown_shield(self):
        oz = fresh()
        with self.assertRaises(UnknownShieldError):
            oz.collapse("nope", 1)

    def test_collapse_bad_reason(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 1)
        with self.assertRaises(BadCollapseError):
            oz.collapse("sh1", 2, reason="because-i-said-so")


class TestTierView(unittest.TestCase):
    def test_tier_is_pure_view(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 1, tier="global")
        self.assertEqual(oz.tier("sh1"), "global")
        # View consumes no seq: a rewind is still a rewind.
        with self.assertRaises(SeqOrderError):
            oz.shield("sh2", "other.example.com", 1)

    def test_tier_unknown_shield(self):
        oz = fresh()
        with self.assertRaises(UnknownShieldError):
            oz.tier("nope")
        with self.assertRaises(UnknownShieldError):
            oz.status("nope")


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_refused(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 5)
        with self.assertRaises(SeqOrderError):
            oz.shield("sh2", "other.example.com", 5)

    def test_seq_bool_and_negative_refused(self):
        oz = fresh()
        with self.assertRaises(SeqOrderError):
            oz.shield("sh1", "origin.example.com", True)
        with self.assertRaises(SeqOrderError):
            oz.shield("sh1", "origin.example.com", -1)

    def test_failed_mutation_consumes_seq(self):
        oz = fresh()
        with self.assertRaises(BadShieldError):
            oz.shield("sh1", "origin.example.com", 1, region="moon")
        # The failed shield burned seq 1; only strictly greater passes.
        with self.assertRaises(SeqOrderError):
            oz.shield("sh1", "origin.example.com", 1)
        rec = oz.shield("sh1", "origin.example.com", 2)
        self.assertTrue(rec.verify())


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        oz = fresh()
        oz.shield("sh1", "origin.example.com", 1)
        oz.collapse("sh1", 2)
        kinds = [e["kind"] for e in oz.audit_log()]
        self.assertIn("origin-shield.shield-pinned", kinds)
        self.assertIn("origin-shield.shield-collapsed", kinds)
        for e in oz.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], ORIGIN_SHIELD_VERSION)
            self.assertIsInstance(e["seq"], int)
            # Origin hostnames never cross the audit boundary.
            self.assertNotIn("origin", e["detail"])

    def test_rejected_audit(self):
        oz = fresh()
        with self.assertRaises(BadShieldError):
            oz.shield("sh1", "origin.example.com", 1, region="moon")
        self.assertEqual(
            oz.audit_log()[-1]["kind"], "origin-shield.rejected")

    def test_audit_bad_kind(self):
        with self.assertRaises(OriginShieldError):
            origin_shield_audit_event("nope", {}, 1)

    def test_audit_origin_ban(self):
        with self.assertRaises(OriginShieldError):
            origin_shield_audit_event(
                "origin-shield.shield-pinned",
                {"origin": "secret.example.com"}, 1)

    def test_views(self):
        oz = fresh()
        oz.shield("b", "b.example.com", 1)
        oz.shield("a", "a.example.com", 2)
        oz.collapse("b", 3)
        self.assertEqual(oz.shield_ids(), ["a", "b"])
        self.assertEqual(oz.active_ids(), ["a"])
        self.assertIsNone(oz.collapse_of("a"))
        with self.assertRaises(OriginShieldError):
            oz.collapse_record("col-999")


if __name__ == "__main__":
    unittest.main()
