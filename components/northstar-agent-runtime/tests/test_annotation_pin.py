"""Annotation-hint pinning tests.

The layer under test: ``components/northstar-agent-runtime/annotation_pin.py``.

These tests are not a pile of isolated assertions about parts.  Each one
drives a *path*: a session pins a tool, the next session meets the same tool,
and the verdict must follow the direction of any change.

Sources: outsideloop, "A tool that says it's read-only is making a claim,
not giving you a permission" (Moltbook), plus the MCP spec line it quotes:
"clients MUST consider tool annotations to be untrusted unless they come from
trusted servers."
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("annotation_pin")

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}}
OTHER_SCHEMA = {"type": "object", "properties": {"path": {"type": "integer"}}}

READ_ONLY = {"read_only": True, "destructive": False}
WRITE_CAPABLE = {"read_only": False, "destructive": True}


def _registry(*trusted_servers):
    registry = ap.AnnotationRegistry()
    for server in trusted_servers:
        registry.trust.trust(server)
    return registry


class PinAndVerifyTests(unittest.TestCase):
    def test_pin_then_verify_round_trip_is_ok(self):
        registry = _registry("fs")
        pin = registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(pin.server, "fs")
        self.assertEqual(pin.tool, "read")
        self.assertTrue(pin.hint_digest.startswith("sha256:"))
        outcome = registry.verify("fs", "read", READ_ONLY, SCHEMA)
        self.assertEqual(outcome, ap.OK)
        self.assertFalse(
            registry.requires_confirmation("fs", "read", READ_ONLY, SCHEMA)
        )

    def test_from_dict_refuses_a_pin_without_a_digest(self):
        with self.assertRaises(ap.AnnotationPinError):
            ap.AnnotationPin.from_dict(
                {"server": "fs", "tool": "read", "hint_digest": ""}
            )
        with self.assertRaises(ap.AnnotationPinError):
            ap.AnnotationPin.from_dict({"server": "fs", "tool": "read"})

    def test_from_dict_round_trips_a_real_pin(self):
        registry = _registry("fs")
        pin = registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator", "t0")
        rebuilt = ap.AnnotationPin.from_dict(pin.to_dict())
        self.assertEqual(rebuilt, pin)

    def test_unpinned_tool_is_unpinned_and_needs_confirmation(self):
        registry = _registry("fs")
        self.assertEqual(registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.UNPINNED)
        self.assertTrue(
            registry.requires_confirmation("fs", "read", READ_ONLY, SCHEMA)
        )
        self.assertIn("no annotation pin", registry.rearm_reason("fs", "read", READ_ONLY, SCHEMA))


class SafeFlipTests(unittest.TestCase):
    def test_safe_flip_is_accepted_and_updates_the_pin(self):
        registry = _registry("fs")
        registry.pin("fs", "write", WRITE_CAPABLE, SCHEMA, "operator")
        before = registry.get_pin("fs", "write").hint_digest

        outcome = registry.verify("fs", "write", READ_ONLY, SCHEMA)
        self.assertEqual(outcome, ap.SAFE_FLIP)

        # The pin is not moved by a mere verification -- only by an explicit
        # acceptance of the safe flip.
        self.assertEqual(registry.get_pin("fs", "write").hint_digest, before)

        registry.accept_safe_flip("fs", "write", READ_ONLY, SCHEMA)
        after = registry.get_pin("fs", "write").hint_digest
        self.assertNotEqual(after, before)
        self.assertEqual(registry.verify("fs", "write", READ_ONLY, SCHEMA), ap.OK)

    def test_safe_flip_does_not_ask_for_confirmation(self):
        registry = _registry("fs")
        registry.pin("fs", "write", WRITE_CAPABLE, SCHEMA, "operator")
        self.assertFalse(
            registry.requires_confirmation("fs", "write", READ_ONLY, SCHEMA)
        )
        self.assertEqual(registry.rearm_reason("fs", "write", READ_ONLY, SCHEMA), "")

    def test_a_dangerous_flip_cannot_be_accepted_as_safe(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertIsNone(
            registry.accept_safe_flip("fs", "read", WRITE_CAPABLE, SCHEMA)
        )


class DangerousFlipTests(unittest.TestCase):
    def test_dangerous_flip_is_detected_and_the_pin_is_not_updated(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        before = registry.get_pin("fs", "read").hint_digest

        outcome = registry.verify("fs", "read", WRITE_CAPABLE, SCHEMA)
        self.assertEqual(outcome, ap.DANGEROUS_FLIP)

        # The pin still holds the old claim: a dangerous flip must not be
        # able to move the pin by itself.
        self.assertEqual(registry.get_pin("fs", "read").hint_digest, before)
        self.assertEqual(registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.OK)

    def test_dangerous_flip_re_arms_confirmation(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertTrue(
            registry.requires_confirmation("fs", "read", WRITE_CAPABLE, SCHEMA)
        )
        reason = registry.rearm_reason("fs", "read", WRITE_CAPABLE, SCHEMA)
        self.assertIn("widened", reason)

    def test_only_a_human_re_pin_releases_a_dangerous_flip(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "read", WRITE_CAPABLE, SCHEMA), ap.DANGEROUS_FLIP)

        # The human re-pins the new claim.
        registry.pin("fs", "read", WRITE_CAPABLE, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "read", WRITE_CAPABLE, SCHEMA), ap.OK)
        self.assertFalse(
            registry.requires_confirmation("fs", "read", WRITE_CAPABLE, SCHEMA)
        )

    def test_the_dangerous_flip_is_visible_in_the_next_session_too(self):
        """The whole point: the flip is not a one-shot event.

        A session that flips the hint and then leaves it flipped must keep
        asking for confirmation -- until a human re-pins.
        """
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        for _session in range(3):
            self.assertEqual(
                registry.verify("fs", "read", WRITE_CAPABLE, SCHEMA), ap.DANGEROUS_FLIP
            )
            self.assertTrue(
                registry.requires_confirmation("fs", "read", WRITE_CAPABLE, SCHEMA)
            )


class FailClosedTests(unittest.TestCase):
    def test_missing_annotation_is_write_capable_and_asks_for_confirmation(self):
        registry = _registry("fs")
        registry.pin("fs", "write", WRITE_CAPABLE, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "write", None, SCHEMA), ap.DRIFT)
        self.assertTrue(registry.requires_confirmation("fs", "write", None, SCHEMA))
        self.assertFalse(ap.effective_read_only(None))

    def test_missing_annotation_over_a_read_only_pin_is_a_dangerous_flip(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "read", None, SCHEMA), ap.DANGEROUS_FLIP)
        self.assertTrue(registry.requires_confirmation("fs", "read", None, SCHEMA))

    def test_malformed_annotation_is_write_capable(self):
        registry = _registry("fs")
        for malformed in (
            "not-a-dict",
            ["read_only"],
            {"read_only": True},
            {"destructive": False},
            {"read_only": "yes", "destructive": False},
            {"read_only": True, "destructive": 1},
            {},
        ):
            with self.subTest(malformed=malformed):
                self.assertIsNone(ap.normalize_annotations(malformed))
                self.assertEqual(ap.capability_rank(malformed), ap.RANK_WRITE)
                self.assertFalse(ap.effective_read_only(malformed))
                self.assertTrue(
                    registry.requires_confirmation("fs", "t", malformed, SCHEMA)
                )

    def test_contradictory_claims_fail_closed_to_write_capable(self):
        contradictory = {"read_only": True, "destructive": True}
        self.assertEqual(ap.capability_rank(contradictory), ap.RANK_WRITE)
        self.assertFalse(ap.effective_read_only(contradictory))


class TrustTests(unittest.TestCase):
    def test_an_untrusted_servers_annotations_are_ignored(self):
        registry = ap.AnnotationRegistry()  # no trust written at all
        registry.pin("rogue", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(
            registry.verify("rogue", "read", READ_ONLY, SCHEMA), ap.UNPINNED
        )
        self.assertTrue(
            registry.requires_confirmation("rogue", "read", READ_ONLY, SCHEMA)
        )
        self.assertIn("trust table", registry.rearm_reason("rogue", "read", READ_ONLY, SCHEMA))

    def test_trust_is_per_server(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        registry.pin("rogue", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.OK)
        self.assertEqual(
            registry.verify("rogue", "read", READ_ONLY, SCHEMA), ap.UNPINNED
        )

    def test_distrusting_a_server_takes_its_annotations_back(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        self.assertEqual(registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.OK)
        registry.trust.distrust("fs")
        self.assertEqual(
            registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.UNPINNED
        )
        self.assertTrue(
            registry.requires_confirmation("fs", "read", READ_ONLY, SCHEMA)
        )


class ArtifactNotVersionTests(unittest.TestCase):
    def test_version_is_not_part_of_the_pin(self):
        """The version string is not part of the hint digest.

        Servers repoint behaviour behind a stable version number, so a
        version bump alone is not a change of effect.  (This test drives the
        digest directly, because ``verify`` takes the schema, not a version.)
        """
        digest = ap.hint_digest(READ_ONLY, SCHEMA)
        self.assertEqual(digest, ap.hint_digest(READ_ONLY, SCHEMA))
        self.assertNotIn("version", ap._canonical({"hints": READ_ONLY, "schema_hash": ap.hash_schema(SCHEMA)}))

    def test_same_hints_and_schema_verify_ok_regardless_of_the_version_label(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        # The caller reports a new version string but the same schema and
        # the same hints: the artifact did not move.
        self.assertEqual(registry.verify("fs", "read", READ_ONLY, SCHEMA), ap.OK)
        self.assertFalse(
            registry.requires_confirmation("fs", "read", READ_ONLY, SCHEMA)
        )

    def test_schema_change_behind_a_stable_version_is_drift(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        outcome = registry.verify("fs", "read", READ_ONLY, OTHER_SCHEMA)
        self.assertEqual(outcome, ap.DRIFT)
        self.assertTrue(
            registry.requires_confirmation("fs", "read", READ_ONLY, OTHER_SCHEMA)
        )
        self.assertIn("drifted", registry.rearm_reason("fs", "read", READ_ONLY, OTHER_SCHEMA))


class CanonicalDigestTests(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self):
        first = {"read_only": True, "destructive": False, "title": "Read a file"}
        second = {"title": "Read a file", "destructive": False, "read_only": True}
        self.assertEqual(ap.hint_digest(first, SCHEMA), ap.hint_digest(second, SCHEMA))

    def test_the_digest_changes_when_a_hint_changes(self):
        self.assertNotEqual(
            ap.hint_digest(READ_ONLY, SCHEMA), ap.hint_digest(WRITE_CAPABLE, SCHEMA)
        )

    def test_the_digest_changes_when_the_schema_changes(self):
        self.assertNotEqual(
            ap.hint_digest(READ_ONLY, SCHEMA), ap.hint_digest(READ_ONLY, OTHER_SCHEMA)
        )

    def test_alias_spellings_normalise_to_the_same_digest(self):
        camel = {"readOnlyHint": True, "destructiveHint": False}
        self.assertEqual(ap.hint_digest(camel, SCHEMA), ap.hint_digest(READ_ONLY, SCHEMA))


class EndToEndPathTests(unittest.TestCase):
    def test_the_full_path_from_discovery_to_drift(self):
        """One tool, one operator, many sessions.

        This drives the whole path in order, the way a host would:
        discover and pin, meet the tool again, meet a narrowed tool, meet a
        widened tool, meet a tool with no annotations, meet a tool whose
        schema moved.
        """
        registry = _registry("fs")
        schema = {"type": "object", "properties": {"path": {"type": "string"}}}

        # (a) discovery pins the hint set.
        registry.pin("fs", "doc", READ_ONLY, schema, "operator")
        self.assertEqual(registry.verify("fs", "doc", READ_ONLY, schema), ap.OK)
        self.assertFalse(registry.requires_confirmation("fs", "doc", READ_ONLY, schema))

        # (b) a safe flip: destructive -> read-only, silently accepted.
        registry.pin("fs", "doc2", WRITE_CAPABLE, schema, "operator")
        self.assertEqual(registry.verify("fs", "doc2", READ_ONLY, schema), ap.SAFE_FLIP)
        registry.accept_safe_flip("fs", "doc2", READ_ONLY, schema)
        self.assertEqual(registry.verify("fs", "doc2", READ_ONLY, schema), ap.OK)
        self.assertFalse(registry.requires_confirmation("fs", "doc2", READ_ONLY, schema))

        # (c) a dangerous flip: read-only -> destructive, re-armed.
        self.assertEqual(registry.verify("fs", "doc", WRITE_CAPABLE, schema), ap.DANGEROUS_FLIP)
        self.assertTrue(registry.requires_confirmation("fs", "doc", WRITE_CAPABLE, schema))

        # (d) missing annotations: write-capable, re-armed.
        self.assertTrue(registry.requires_confirmation("fs", "doc", None, schema))

        # (e) the schema moved behind a stable version: drift, re-armed.
        moved = {"type": "object", "properties": {"path": {"type": "integer"}}}
        self.assertEqual(registry.verify("fs", "doc", READ_ONLY, moved), ap.DRIFT)
        self.assertTrue(registry.requires_confirmation("fs", "doc", READ_ONLY, moved))

    def test_a_restored_pin_without_material_fails_closed_to_drift(self):
        registry = _registry("fs")
        registry.pin("fs", "read", READ_ONLY, SCHEMA, "operator")
        exported = registry.export_pins()

        restored = ap.AnnotationRegistry()
        restored.trust.trust("fs")
        self.assertEqual(restored.restore_pins(exported), 1)
        # The digest is there, but the pinned claim is not: a flip could not
        # be classified, so the verdict fails closed to drift.
        self.assertEqual(restored.verify("fs", "read", READ_ONLY, SCHEMA), ap.DRIFT)
        self.assertTrue(restored.requires_confirmation("fs", "read", READ_ONLY, SCHEMA))


if __name__ == "__main__":
    unittest.main()
