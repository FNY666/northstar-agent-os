"""Targeted tests for text_to_speech.py (house style: unittest, no wall-clock)."""

import ast
import sys
import unittest
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import text_to_speech as tts_mod
from text_to_speech import (
    VERSION,
    SCHEMA,
    TextToSpeech,
    TextToSpeechError,
    DuplicateVoiceError,
    UnknownVoiceError,
    InvalidVoiceError,
    InvalidTextError,
    InvalidProsodyError,
    BadSSMLError,
    UnknownSynthesisError,
    SequenceError,
    text_to_speech_audit_event,
)


def make_engine():
    e = TextToSpeech()
    e.register_voice("v1", "Ada", "en-US", "feminine", 1)
    return e


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "text-to-speech.v1")
        self.assertEqual(SCHEMA, "northstar.text-to-speech.v1")

    def test_stdlib_only(self):
        src = Path(tts_mod.__file__).read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib", "json", "re", "threading", "dataclasses",
            "fractions", "html", "html.parser", "typing", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestVoices(unittest.TestCase):
    def test_register_roundtrip(self):
        e = TextToSpeech()
        rec = e.register_voice("v1", "Ada", "en-US", "feminine", 1)
        self.assertEqual(e.voice("v1").name, "Ada")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.digest, e.voice("v1").digest)

    def test_digest_determinism(self):
        a, b = TextToSpeech(), TextToSpeech()
        r1 = a.register_voice("v1", "Ada", "en-US", "feminine", 1)
        r2 = b.register_voice("v1", "Ada", "en-US", "feminine", 1)
        self.assertEqual(r1.digest, r2.digest)

    def test_duplicate_voice(self):
        e = make_engine()
        with self.assertRaises(DuplicateVoiceError):
            e.register_voice("v1", "Other", "en-GB", "masculine", 2)

    def test_bad_language_tag(self):
        e = TextToSpeech()
        with self.assertRaises(InvalidVoiceError):
            e.register_voice("v1", "Ada", "not-a-tag!", "feminine", 1)

    def test_bad_gender(self):
        e = TextToSpeech()
        with self.assertRaises(InvalidVoiceError):
            e.register_voice("v1", "Ada", "en-US", "alien", 1)

    def test_unknown_voice(self):
        e = TextToSpeech()
        with self.assertRaises(UnknownVoiceError):
            e.voice("nope")

    def test_voices_filter(self):
        e = make_engine()
        e.register_voice("v2", "Bruno", "de-DE", "masculine", 2)
        self.assertEqual(len(e.voices()), 2)
        self.assertEqual([v.voice_id for v in e.voices(language="de-DE")], ["v2"])


class TestSynthesize(unittest.TestCase):
    def test_happy_path(self):
        e = make_engine()
        rec = e.synthesize("Hello, world.", "v1", 2)
        self.assertEqual(rec.synth_id, "synth-1")
        self.assertEqual(rec.char_count, 13)
        self.assertEqual(
            Fraction(rec.duration_num, rec.duration_den), Fraction(13, 15))
        self.assertTrue(rec.text_digest.startswith("sha256:"))
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_determinism(self):
        a, b = make_engine(), make_engine()
        r1 = a.synthesize("abc", "v1", 2)
        r2 = b.synthesize("abc", "v1", 2)
        self.assertEqual(r1.digest, r2.digest)
        self.assertEqual(r1.text_digest, r2.text_digest)

    def test_rate_scales_duration(self):
        e = make_engine()
        rec = e.synthesize("abcdef", "v1", 2, rate=2.0)
        self.assertEqual(Fraction(rec.duration_num, rec.duration_den), Fraction(6, 30))

    def test_empty_text(self):
        e = make_engine()
        with self.assertRaises(InvalidTextError):
            e.synthesize("   ", "v1", 2)

    def test_unknown_voice(self):
        e = make_engine()
        with self.assertRaises(UnknownVoiceError):
            e.synthesize("hi", "nope", 2)

    def test_bad_rate(self):
        e = make_engine()
        with self.assertRaises(InvalidProsodyError):
            e.synthesize("hi", "v1", 2, rate=3.0)
        with self.assertRaises(InvalidProsodyError):
            e.synthesize("hi", "v1", 3, rate=0.1)

    def test_text_too_long(self):
        e = make_engine()
        with self.assertRaises(InvalidTextError):
            e.synthesize("x" * 10_001, "v1", 2)

    def test_lookup(self):
        e = make_engine()
        e.synthesize("hi", "v1", 2)
        self.assertEqual(e.synthesis("synth-1").voice_id, "v1")
        self.assertEqual(e.syntheses(), ("synth-1",))
        with self.assertRaises(UnknownSynthesisError):
            e.synthesis("synth-99")


class TestSSML(unittest.TestCase):
    def test_happy_path(self):
        e = make_engine()
        rec = e.ssml("<speak>Hello <break/>world.</speak>", "v1", 2)
        self.assertEqual(rec.tags, ("speak", "break"))
        self.assertEqual(rec.char_count, len("Hello world."))
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_unpinned_tag(self):
        e = make_engine()
        with self.assertRaises(BadSSMLError):
            e.ssml("<speak>Hello <blink/>x.</speak>", "v1", 2)

    def test_mismatched_tags(self):
        e = make_engine()
        with self.assertRaises(BadSSMLError):
            e.ssml("<speak>Hello <emphasis>x.</speak>", "v1", 2)

    def test_missing_speak_root(self):
        e = make_engine()
        with self.assertRaises(BadSSMLError):
            e.ssml("<emphasis>hi</emphasis>", "v1", 2)

    def test_empty_text(self):
        e = make_engine()
        with self.assertRaises(BadSSMLError):
            e.ssml("<speak></speak>", "v1", 2)

    def test_unknown_voice(self):
        e = make_engine()
        with self.assertRaises(UnknownVoiceError):
            e.ssml("<speak>hi</speak>", "nope", 2)

    def test_synthesis_view_for_ssml(self):
        e = make_engine()
        e.ssml("<speak>hi</speak>", "v1", 2)
        view = e.synthesis("synth-1")
        self.assertEqual(view.char_count, 2)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_strictly_increasing(self):
        e = make_engine()
        with self.assertRaises(SequenceError):
            e.register_voice("v2", "B", "en-US", "neutral", 1)
        with self.assertRaises(SequenceError):
            e.register_voice("v2", "B", "en-US", "neutral", True)

    def test_failed_mutation_consumes_seq(self):
        e = make_engine()
        with self.assertRaises(DuplicateVoiceError):
            e.register_voice("v1", "X", "en-US", "feminine", 2)
        # seq 2 is consumed; next must be 3
        with self.assertRaises(SequenceError):
            e.register_voice("v2", "B", "en-US", "neutral", 2)
        rec = e.register_voice("v2", "B", "en-US", "neutral", 3)
        self.assertEqual(rec.seq, 3)

    def test_audit_shapes(self):
        e = make_engine()
        e.synthesize("hi", "v1", 2)
        e.ssml("<speak>yo</speak>", "v1", 3)
        log = e.audit_log()
        kinds = [ev["kind"] for ev in log]
        self.assertEqual(kinds, [
            "voice-registered", "synthesized", "ssml-synthesized"])
        for ev in log:
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertTrue(ev["digest"].startswith("sha256:"))
            self.assertNotIn("text", ev["detail"])
            for v in ev["detail"].values():
                self.assertNotIn("hi", str(v))
                self.assertNotIn("yo", str(v))

    def test_audit_bad_kind(self):
        with self.assertRaises(TextToSpeechError):
            text_to_speech_audit_event("bogus", 1, {})

    def test_main(self):
        tts_mod.main()


if __name__ == "__main__":
    unittest.main()
