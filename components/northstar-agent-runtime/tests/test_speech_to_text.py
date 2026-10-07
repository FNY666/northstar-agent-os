"""Tests for speech_to_text (Whisper-style interface, simulated)."""

import ast
import unittest
from pathlib import Path

from speech_to_text import (
    AUDIT_SCHEMA,
    SCHEMA_PIN,
    SPEECH_TO_TEXT_VERSION,
    DuplicateAudioError,
    SeqOrderError,
    SpeechToText,
    UnknownAudioError,
    ValidationError,
    speech_to_text_audit_event,
)

DIGEST = "ab" * 32


def _stt() -> SpeechToText:
    return SpeechToText()


def _register(stt, aid="clip-1", seq=1, **kw):
    args = dict(
        audio_id=aid,
        duration_ms=60_000,
        audio_digest=DIGEST,
        transcript_claim="one two three four five six seven eight nine ten",
        seq=seq,
    )
    args.update(kw)
    return stt.register_audio(**args)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(SPEECH_TO_TEXT_VERSION, "speech-to-text.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.speech-to-text.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        src = (Path(__file__).parent.parent / "speech_to_text.py").read_text()
        allowed = {"__future__", "hashlib", "re", "threading", "dataclasses",
                   "typing", "json", "canonical_json"}
        tree = ast.parse(src)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module.split(".")[0])
        self.assertLessEqual(imports, allowed, imports - allowed)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        stt = _stt()
        clip = _register(stt)
        self.assertEqual(clip.audio_id, "clip-1")
        self.assertTrue(clip.pin.startswith("sha256:"))
        self.assertEqual(stt.clip("clip-1").pin, clip.pin)

    def test_duplicate_refused(self):
        stt = _stt()
        _register(stt)
        with self.assertRaises(DuplicateAudioError):
            _register(stt, seq=2)

    def test_bad_inputs(self):
        stt = _stt()
        # failed mutations consume their seq (fail-closed ledger position)
        n = [1]

        def bad(**kw):
            n[0] += 1
            with self.assertRaises(ValidationError):
                _register(stt, seq=n[0], **kw)

        bad(duration_ms=0)
        bad(duration_ms=True)
        bad(audio_digest="zz")
        bad(transcript_claim=123)
        bad(language_code="english!")
        bad(language_probs=[("en", 500)])
        bad(speaker_count=0)

    def test_seq_monotonic(self):
        stt = _stt()
        _register(stt, seq=5)
        with self.assertRaises(SeqOrderError):
            _register(stt, aid="clip-2", seq=5)
        with self.assertRaises(ValidationError):
            _register(stt, aid="clip-2", seq=True)


class TestTranscribe(unittest.TestCase):
    def test_segments_and_timing(self):
        stt = _stt()
        _register(stt)
        tr = stt.transcribe("clip-1", 2)
        self.assertEqual(tr.audio_id, "clip-1")
        self.assertEqual(tr.task, "transcribe")
        self.assertTrue(tr.pin.startswith("sha256:"))
        self.assertTrue(tr.segments)
        self.assertEqual(tr.segments[0].start_ms, 0)
        self.assertEqual(tr.segments[-1].end_ms, 60_000)
        for s in tr.segments:
            self.assertLess(s.start_ms, s.end_ms)
            self.assertLessEqual(len(s.words), 8)

    def test_determinism(self):
        s1, s2 = _stt(), _stt()
        _register(s1)
        _register(s2)
        t1 = s1.transcribe("clip-1", 2)
        t2 = s2.transcribe("clip-1", 2)
        self.assertEqual([s.as_dict() for s in t1.segments],
                         [s.as_dict() for s in t2.segments])

    def test_unknown_audio(self):
        stt = _stt()
        with self.assertRaises(UnknownAudioError):
            stt.transcribe("nope", 1)

    def test_bad_task(self):
        stt = _stt()
        _register(stt)
        with self.assertRaises(ValidationError):
            stt.transcribe("clip-1", 2, task="summarize")


class TestDiarize(unittest.TestCase):
    def test_spans_shape(self):
        stt = _stt()
        _register(stt, speaker_count=2)
        dz = stt.diarize("clip-1", 2)
        self.assertEqual(dz.speaker_count, 2)
        self.assertTrue(dz.spans)
        self.assertEqual(dz.spans[0].start_ms, 0)
        for a, b in zip(dz.spans, dz.spans[1:]):
            self.assertEqual(a.end_ms, b.start_ms)
        for s in dz.spans:
            self.assertRegex(s.speaker, r"^SPEAKER_\d{2}$")

    def test_unknown_audio(self):
        stt = _stt()
        with self.assertRaises(UnknownAudioError):
            stt.diarize("nope", 1)


class TestLanguage(unittest.TestCase):
    def test_distribution(self):
        stt = _stt()
        _register(stt, language_code="en",
                  language_probs=[("en", 950), ("es", 50)])
        lg = stt.language("clip-1", 2)
        self.assertEqual(lg.primary_code, "en")
        self.assertEqual(lg.probabilities[0], ("en", 950))
        self.assertEqual(sum(p for _, p in lg.probabilities), 1000)

    def test_unknown_audio(self):
        stt = _stt()
        with self.assertRaises(UnknownAudioError):
            stt.language("nope", 1)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        stt = _stt()
        _register(stt)
        stt.transcribe("clip-1", 2)
        stt.diarize("clip-1", 3)
        stt.language("clip-1", 4)
        kinds = [e["kind"] for e in stt.audit_log()]
        self.assertEqual(
            kinds, ["registered", "transcribed", "diarized", "language-detected"]
        )
        for e in stt.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertNotIn("transcript_claim", e)

    def test_bad_kind(self):
        with self.assertRaises(ValidationError):
            speech_to_text_audit_event("nope", 1, "clip-1")


if __name__ == "__main__":
    unittest.main()
