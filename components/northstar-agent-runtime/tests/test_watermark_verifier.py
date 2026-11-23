"""Tests for watermark_verifier."""

import re
import unittest

from watermark_verifier import (
    ALGORITHM,
    SCHEMA_PIN,
    TAG_BITS,
    WATERMARK_VERIFIER_VERSION,
    Watermark,
    embed_watermark,
    key_fingerprint,
    strip_watermark,
    verify_watermark,
    watermark_audit_event,
    watermark_info,
)

CONTENT = "The quick brown fox jumps over the lazy dog."
KEY = "test-key-1"


class VersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(WATERMARK_VERIFIER_VERSION, "watermark-verifier.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.watermark-verifier.v1")

    def test_algorithm(self):
        self.assertEqual(ALGORITHM, "hmac-sha256-zwsp.v1")

    def test_tag_bits(self):
        self.assertEqual(TAG_BITS, 64)


class Embed(unittest.TestCase):
    def test_embed_changes_bytes(self):
        marked = embed_watermark(CONTENT, KEY)
        self.assertNotEqual(marked, CONTENT)

    def test_embed_invisible(self):
        marked = embed_watermark(CONTENT, KEY)
        self.assertEqual(strip_watermark(marked), CONTENT)

    def test_embed_empty_content_raises(self):
        with self.assertRaises(ValueError):
            embed_watermark("", KEY)

    def test_embed_empty_key_raises(self):
        with self.assertRaises(ValueError):
            embed_watermark(CONTENT, "")

    def test_embed_non_str_content_raises(self):
        with self.assertRaises(TypeError):
            embed_watermark(123, KEY)

    def test_embed_non_str_key_raises(self):
        with self.assertRaises(TypeError):
            embed_watermark(CONTENT, None)

    def test_embed_idempotent_same_key(self):
        once = embed_watermark(CONTENT, KEY)
        twice = embed_watermark(once, KEY)
        self.assertTrue(verify_watermark(twice, KEY))
        self.assertEqual(strip_watermark(twice), CONTENT)

    def test_embed_different_keys_differ(self):
        a = embed_watermark(CONTENT, "key-a")
        b = embed_watermark(CONTENT, "key-b")
        self.assertNotEqual(a, b)


class Verify(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(verify_watermark(embed_watermark(CONTENT, KEY), KEY))

    def test_wrong_key_fails(self):
        marked = embed_watermark(CONTENT, KEY)
        self.assertFalse(verify_watermark(marked, "wrong-key"))

    def test_unmarked_fails(self):
        self.assertFalse(verify_watermark(CONTENT, KEY))

    def test_tampered_content_fails(self):
        marked = embed_watermark(CONTENT, KEY)
        self.assertFalse(verify_watermark(marked + "X", KEY))

    def test_tampered_bits_fail(self):
        marked = embed_watermark(CONTENT, KEY)
        tampered = marked[:-1] + ("\u200b" if marked[-1] == "\u200c" else "\u200c")
        self.assertFalse(verify_watermark(tampered, KEY))

    def test_empty_content_fails_closed(self):
        self.assertFalse(verify_watermark("", KEY))

    def test_empty_key_fails_closed(self):
        marked = embed_watermark(CONTENT, KEY)
        self.assertFalse(verify_watermark(marked, ""))

    def test_non_str_raises(self):
        with self.assertRaises(TypeError):
            verify_watermark(None, KEY)
        with self.assertRaises(TypeError):
            verify_watermark(CONTENT, 42)


class WatermarkRecord(unittest.TestCase):
    def test_info_full_match(self):
        info = watermark_info(embed_watermark(CONTENT, KEY), KEY)
        self.assertIsNotNone(info)
        self.assertEqual(info.algorithm, ALGORITHM)
        self.assertEqual(info.confidence, 1.0)

    def test_info_none_on_unmarked(self):
        self.assertIsNone(watermark_info(CONTENT, KEY))

    def test_key_id_shape(self):
        info = watermark_info(embed_watermark(CONTENT, KEY), KEY)
        self.assertTrue(re.fullmatch(r"sha256:[0-9a-f]{64}", info.key_id))

    def test_key_id_does_not_leak_key(self):
        info = watermark_info(embed_watermark(CONTENT, KEY), KEY)
        self.assertNotIn(KEY, info.key_id)

    def test_key_id_stable(self):
        self.assertEqual(key_fingerprint(KEY), key_fingerprint(KEY))

    def test_key_id_differs_per_key(self):
        self.assertNotEqual(key_fingerprint("a"), key_fingerprint("b"))

    def test_watermark_frozen(self):
        info = watermark_info(embed_watermark(CONTENT, KEY), KEY)
        with self.assertRaises(Exception):
            info.confidence = 0.5  # type: ignore[misc]

    def test_watermark_bad_confidence_rejected(self):
        with self.assertRaises(ValueError):
            Watermark(algorithm=ALGORITHM,
                      key_id=key_fingerprint(KEY), confidence=1.5)

    def test_watermark_bad_key_id_rejected(self):
        with self.assertRaises(ValueError):
            Watermark(algorithm=ALGORITHM, key_id="nope", confidence=1.0)

    def test_as_dict_schema(self):
        info = watermark_info(embed_watermark(CONTENT, KEY), KEY)
        d = info.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["confidence"], 1.0)


class AuditEvent(unittest.TestCase):
    def test_event_valid(self):
        ev = watermark_audit_event(embed_watermark(CONTENT, KEY), KEY, 7)
        self.assertTrue(ev["valid"])
        self.assertEqual(ev["confidence"], 1.0)
        self.assertEqual(ev["seq"], 7)

    def test_event_invalid(self):
        ev = watermark_audit_event(CONTENT, KEY, 7)
        self.assertFalse(ev["valid"])
        self.assertEqual(ev["confidence"], 0.0)

    def test_event_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            watermark_audit_event(CONTENT, KEY, -1)
        with self.assertRaises(ValueError):
            watermark_audit_event(CONTENT, KEY, True)


class Standalone(unittest.TestCase):
    def test_module_importable_standalone(self):
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location(
            "watermark_verifier_sa",
            "watermark_verifier.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["watermark_verifier_sa"] = mod  # dataclasses need this
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.modules.pop("watermark_verifier_sa", None)
        marked = mod.embed_watermark(CONTENT, KEY)
        self.assertTrue(mod.verify_watermark(marked, KEY))


if __name__ == "__main__":
    unittest.main()
