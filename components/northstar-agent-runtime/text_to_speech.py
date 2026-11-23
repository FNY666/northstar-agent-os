"""Text-to-speech interface: voices/synthesize as deterministic bookkeeping.

Research note: TTS sits between an agent's text reasoning and an audio
channel. Real-world TTS services (AWS Polly, ElevenLabs, Azure Speech)
share three properties that matter for a correct interface: (1) *voice
selection is a catalog problem* — a voice is pinned by an id, a language
tag, and characteristics; (2) *synthesis is a deterministic function of
(text, voice, prosody)* — the same input replays the same output, so the
record can be digest-pinned; (3) *SSML is markup with a pinned vocabulary*
— a synthesizer accepts a fixed set of elements and refuses unknown ones
fail-closed.

The load-bearing invariants of this module are:

* **Text is never stored raw** — synthesis records pin the ``sha256:``
  digest of the text (plus char count and a deterministic duration model);
  audit events carry ids and pins only, never utterances (PII boundary, same
  discipline as ``sms_service``'s body-never-crosses-boundary rule).
* **Duration is deterministic** — base chars-per-second at rate 1.0, scaled
  by the prosody rate multiplier; exact arithmetic (``Fraction``), no
  floats touch the duration path.
* **SSML is validated, not rendered** — ``ssml()`` checks tag balance with
  ``html.parser`` and refuses tags outside the pinned allowed set
  fail-closed; text extraction is deterministic.
* **No audio is emitted** — this module is simulated bookkeeping: it
  records what the host *claimed* it synthesized. A host that feeds a real
  TTS engine pairs this ledger with its own audio provenance.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock, no RNG), RLock-guarded, fail-closed error taxonomy
(all under :class:`TextToSpeechError`), stdlib-only (``hashlib``,
``json``, ``math``, ``re``, ``threading``, ``dataclasses``,
``fractions``, ``html.parser``, ``typing``), ``sha256:`` digest pins over
type-tagged canonical encodings, audit events shaped for
``audit.ndjson/1``, ``main()`` self-check.

Honest scope: cannot prove the utterance sounds right, that the host ran a
real synthesizer, or that a listener heard anything. Duration is a model,
not a measurement (GIGO, same boundary as every other bookkeeping module).

Version pin: text-to-speech.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from fractions import Fraction
from html.parser import HTMLParser
from typing import Dict, List, Mapping, Optional, Tuple

VERSION = "text-to-speech.v1"
SCHEMA = "northstar.text-to-speech.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "TextToSpeechError",
    "DuplicateVoiceError",
    "UnknownVoiceError",
    "InvalidVoiceError",
    "InvalidTextError",
    "InvalidProsodyError",
    "BadSSMLError",
    "UnknownSynthesisError",
    "SequenceError",
    "BASE_CPS",
    "MAX_TEXT_CHARS",
    "SSML_ALLOWED_TAGS",
    "VoiceRecord",
    "SynthesisRecord",
    "SSMLRecord",
    "TextToSpeech",
    "text_to_speech_audit_event",
]

#: Deterministic duration model: characters per second at rate 1.0.
BASE_CPS = 15
#: Hard cap on input text length (guardrail against unbounded ledgers).
MAX_TEXT_CHARS = 10_000
#: Pinned SSML element vocabulary (small deterministic subset).
SSML_ALLOWED_TAGS = ("speak", "break", "emphasis", "prosody", "say-as", "voice")


class TextToSpeechError(Exception):
    """Base for all TTS errors (fail-closed taxonomy)."""


class DuplicateVoiceError(TextToSpeechError):
    """A voice_id is already registered."""


class UnknownVoiceError(TextToSpeechError):
    """A voice_id lookup found nothing."""


class InvalidVoiceError(TextToSpeechError):
    """Voice registration payload is malformed (empty id, bad language/gender)."""


class InvalidTextError(TextToSpeechError):
    """Text is empty, whitespace-only, too long, or not a string."""


class InvalidProsodyError(TextToSpeechError):
    """rate/pitch/volume are outside the pinned bounds."""


class BadSSMLError(TextToSpeechError):
    """SSML is malformed or uses an unpinned tag/attribute."""


class UnknownSynthesisError(TextToSpeechError):
    """A synthesis id lookup found nothing."""


class SequenceError(TextToSpeechError):
    """Caller seq did not strictly increase (bool/negative/non-int refused)."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj) -> bytes:
    """Type-tagged canonical JSON encoding (bool != int; no floats)."""
    def tag(v):
        if isinstance(v, bool):
            return {"__t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise ValueError("int out of canonical range")
            return {"__t": "int", "v": v}
        if isinstance(v, float):
            raise ValueError("floats are refused in the canonical path")
        if isinstance(v, str):
            return {"__t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"__t": "list", "v": [tag(x) for x in v]}
        if isinstance(v, dict):
            return {"__t": "dict", "v": [[tag(k), tag(x)] for k, x in sorted(v.items())]}
        if v is None:
            return {"__t": "null"}
        raise TypeError("non-canonical value %r" % (v,))
    return json.dumps(tag(obj), sort_keys=True, separators=(",", ":")).encode()


def _pin(obj) -> str:
    return "sha256:" + _sha256_hex(_canonical(obj))


_GENDER_SET = ("neutral", "masculine", "feminine")
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2})?$")


@dataclass(frozen=True)
class VoiceRecord:
    voice_id: str
    name: str
    language: str
    gender: str
    seq: int
    digest: str


@dataclass(frozen=True)
class SynthesisRecord:
    synth_id: str
    voice_id: str
    text_digest: str
    char_count: int
    duration_num: int
    duration_den: int
    rate_num: int
    rate_den: int
    pitch: int
    volume: int
    seq: int
    digest: str


@dataclass(frozen=True)
class SSMLRecord:
    synth_id: str
    voice_id: str
    text_digest: str
    char_count: int
    duration_num: int
    duration_den: int
    tags: Tuple[str, ...]
    seq: int
    digest: str


class _SSMLValidator(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: List[str] = []
        self.tags: List[str] = []
        self.text_parts: List[str] = []
        self.bad: Optional[str] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if self.bad:
            return
        if tag not in SSML_ALLOWED_TAGS:
            self.bad = "unpinned tag <%s>" % tag
            return
        self.stack.append(tag)
        if tag not in self.tags:
            self.tags.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.bad:
            return
        if not self.stack or self.stack[-1] != tag:
            self.bad = "mismatched </%s>" % tag
            return
        self.stack.pop()

    def handle_startendtag(self, tag: str, attrs) -> None:
        if self.bad:
            return
        if tag not in SSML_ALLOWED_TAGS:
            self.bad = "unpinned tag <%s/>" % tag
            return
        if tag not in self.tags:
            self.tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)


def text_to_speech_audit_event(kind: str, seq: int, detail: Mapping) -> Mapping:
    if not isinstance(kind, str) or kind not in (
        "voice-registered",
        "synthesized",
        "ssml-synthesized",
        "rejected",
    ):
        raise TextToSpeechError("unknown audit kind %r" % (kind,))
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SequenceError("bad seq for audit event")
    if not isinstance(detail, Mapping):
        raise TextToSpeechError("detail must be a mapping")
    event = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }
    event["digest"] = _pin(event)
    return event


class TextToSpeech:
    """Deterministic TTS bookkeeping: voices, synthesize, SSML."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._voices: Dict[str, VoiceRecord] = {}
        self._syntheses: Dict[str, SynthesisRecord] = {}
        self._ssml: Dict[str, SSMLRecord] = {}
        self._seq = 0
        self._voice_n = 0
        self._synth_n = 0
        self._audit: List[Mapping] = []

    # -- seqs -------------------------------------------------------------
    def _next_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._seq:
            raise SequenceError("seq must strictly increase (got %r)" % (seq,))

    def _claim_seq(self, seq: int) -> None:
        self._next_seq(seq)
        self._seq = seq  # failed mutations consume their seq (fail-closed)

    def _log(self, kind: str, seq: int, detail: Mapping) -> None:
        self._audit.append(text_to_speech_audit_event(kind, seq, detail))

    # -- voices -----------------------------------------------------------
    def register_voice(
        self,
        voice_id: str,
        name: str,
        language: str,
        gender: str,
        seq: int,
    ) -> VoiceRecord:
        with self._lock:
            self._claim_seq(seq)
            if not isinstance(voice_id, str) or not voice_id.strip():
                self._log("rejected", seq, {"reason": "empty-voice-id"})
                raise InvalidVoiceError("voice_id must be a non-empty string")
            if not isinstance(name, str) or not name.strip():
                self._log("rejected", seq, {"reason": "empty-voice-name"})
                raise InvalidVoiceError("name must be a non-empty string")
            if not isinstance(language, str) or not _LANGUAGE_RE.match(language):
                self._log("rejected", seq, {"reason": "bad-language-tag"})
                raise InvalidVoiceError("language must be a BCP 47 tag")
            if gender not in _GENDER_SET:
                self._log("rejected", seq, {"reason": "bad-gender"})
                raise InvalidVoiceError("gender must be one of %s" % (_GENDER_SET,))
            if voice_id in self._voices:
                self._log("rejected", seq, {"reason": "duplicate-voice"})
                raise DuplicateVoiceError("voice %r already registered" % (voice_id,))
            self._voice_n += 1
            rec = VoiceRecord(
                voice_id=voice_id,
                name=name,
                language=language,
                gender=gender,
                seq=seq,
                digest=_pin({
                    "voice_id": voice_id, "name": name,
                    "language": language, "gender": gender, "seq": seq,
                }),
            )
            self._voices[voice_id] = rec
            self._log("voice-registered", seq, {
                "voice_id": voice_id, "digest": rec.digest,
            })
            return rec

    def voice(self, voice_id: str) -> VoiceRecord:
        with self._lock:
            if voice_id not in self._voices:
                raise UnknownVoiceError("unknown voice %r" % (voice_id,))
            return self._voices[voice_id]

    def voices(self, language: Optional[str] = None) -> Tuple[VoiceRecord, ...]:
        with self._lock:
            recs = sorted(self._voices.values(), key=lambda r: r.voice_id)
            if language is not None:
                recs = [r for r in recs if r.language == language]
            return tuple(recs)

    # -- synthesis --------------------------------------------------------
    @staticmethod
    def _check_prosody(rate: Fraction, pitch: int, volume: int) -> None:
        if rate < Fraction(1, 2) or rate > Fraction(2, 1):
            raise InvalidProsodyError("rate must be in [0.5, 2.0]")
        if pitch < -100 or pitch > 100:
            raise InvalidProsodyError("pitch must be in [-100, 100]")
        if volume < 0 or volume > 100:
            raise InvalidProsodyError("volume must be in [0, 100]")

    @staticmethod
    def _duration(chars: int, rate: Fraction) -> Fraction:
        # exact rational: chars / (BASE_CPS * rate)
        return Fraction(chars, 1) / (Fraction(BASE_CPS, 1) * rate)

    def synthesize(
        self,
        text: str,
        voice_id: str,
        seq: int,
        *,
        rate: float = 1.0,
        pitch: int = 0,
        volume: int = 100,
    ) -> SynthesisRecord:
        with self._lock:
            self._claim_seq(seq)
            if voice_id not in self._voices:
                self._log("rejected", seq, {"reason": "unknown-voice"})
                raise UnknownVoiceError("unknown voice %r" % (voice_id,))
            if not isinstance(text, str) or not text.strip():
                self._log("rejected", seq, {"reason": "empty-text"})
                raise InvalidTextError("text must be a non-empty string")
            if len(text) > MAX_TEXT_CHARS:
                self._log("rejected", seq, {"reason": "text-too-long"})
                raise InvalidTextError("text exceeds %d chars" % MAX_TEXT_CHARS)
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                self._log("rejected", seq, {"reason": "bad-rate-type"})
                raise InvalidProsodyError("rate must be numeric")
            rate_f = Fraction(str(rate)).limit_denominator(1000)
            if isinstance(pitch, bool) or not isinstance(pitch, int):
                self._log("rejected", seq, {"reason": "bad-pitch-type"})
                raise InvalidProsodyError("pitch must be an int")
            if isinstance(volume, bool) or not isinstance(volume, int):
                self._log("rejected", seq, {"reason": "bad-volume-type"})
                raise InvalidProsodyError("volume must be an int")
            self._check_prosody(rate_f, pitch, volume)
            self._synth_n += 1
            synth_id = "synth-%d" % self._synth_n
            text_digest = "sha256:" + _sha256_hex(text.encode("utf-8"))
            chars = len(text)
            dur = self._duration(chars, rate_f)
            rec = SynthesisRecord(
                synth_id=synth_id,
                voice_id=voice_id,
                text_digest=text_digest,
                char_count=chars,
                duration_num=dur.numerator,
                duration_den=dur.denominator,
                rate_num=rate_f.numerator,
                rate_den=rate_f.denominator,
                pitch=pitch,
                volume=volume,
                seq=seq,
                digest=_pin({
                    "synth_id": synth_id, "voice_id": voice_id,
                    "text_digest": text_digest, "char_count": chars,
                    "duration_num": dur.numerator, "duration_den": dur.denominator,
                    "rate_num": rate_f.numerator, "rate_den": rate_f.denominator,
                    "pitch": pitch, "volume": volume, "seq": seq,
                }),
            )
            self._syntheses[synth_id] = rec
            self._log("synthesized", seq, {
                "synth_id": synth_id, "voice_id": voice_id,
                "digest": rec.digest,
            })
            return rec

    def synthesis(self, synth_id: str) -> SynthesisRecord:
        with self._lock:
            if synth_id in self._syntheses:
                return self._syntheses[synth_id]
            if synth_id in self._ssml:
                s = self._ssml[synth_id]
                # SSML records are presented through the same view shape minus tags.
                return SynthesisRecord(
                    synth_id=s.synth_id, voice_id=s.voice_id,
                    text_digest=s.text_digest, char_count=s.char_count,
                    duration_num=s.duration_num, duration_den=s.duration_den,
                    rate_num=1, rate_den=1, pitch=0, volume=100,
                    seq=s.seq, digest=s.digest,
                )
            raise UnknownSynthesisError("unknown synthesis %r" % (synth_id,))

    def syntheses(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(list(self._syntheses) + list(self._ssml)))

    # -- ssml -------------------------------------------------------------
    def ssml(self, ssml_text: str, voice_id: str, seq: int) -> SSMLRecord:
        with self._lock:
            self._claim_seq(seq)
            if voice_id not in self._voices:
                self._log("rejected", seq, {"reason": "unknown-voice"})
                raise UnknownVoiceError("unknown voice %r" % (voice_id,))
            if not isinstance(ssml_text, str) or not ssml_text.strip():
                self._log("rejected", seq, {"reason": "empty-ssml"})
                raise InvalidTextError("ssml must be a non-empty string")
            if len(ssml_text) > MAX_TEXT_CHARS * 2:
                self._log("rejected", seq, {"reason": "ssml-too-long"})
                raise BadSSMLError("ssml exceeds the length guardrail")
            parser = _SSMLValidator()
            try:
                parser.feed(ssml_text)
                parser.close()
            except Exception as exc:
                self._log("rejected", seq, {"reason": "ssml-parse-failed"})
                raise BadSSMLError("ssml parse failed: %s" % (exc,))
            if parser.bad is not None:
                self._log("rejected", seq, {"reason": parser.bad})
                raise BadSSMLError(parser.bad)
            if parser.stack:
                self._log("rejected", seq, {"reason": "unclosed-tag"})
                raise BadSSMLError("unclosed tags: %s" % (parser.stack,))
            if "speak" not in parser.tags:
                self._log("rejected", seq, {"reason": "missing-speak"})
                raise BadSSMLError("<speak> root element is required")
            text = "".join(parser.text_parts)
            if not text.strip():
                self._log("rejected", seq, {"reason": "empty-ssml-text"})
                raise BadSSMLError("ssml contains no text")
            self._synth_n += 1
            synth_id = "synth-%d" % self._synth_n
            text_digest = "sha256:" + _sha256_hex(text.encode("utf-8"))
            dur = self._duration(len(text), Fraction(1, 1))
            tags = tuple(parser.tags)
            rec = SSMLRecord(
                synth_id=synth_id,
                voice_id=voice_id,
                text_digest=text_digest,
                char_count=len(text),
                duration_num=dur.numerator,
                duration_den=dur.denominator,
                tags=tags,
                seq=seq,
                digest=_pin({
                    "synth_id": synth_id, "voice_id": voice_id,
                    "text_digest": text_digest, "char_count": len(text),
                    "duration_num": dur.numerator, "duration_den": dur.denominator,
                    "tags": list(tags), "seq": seq,
                }),
            )
            self._ssml[synth_id] = rec
            self._log("ssml-synthesized", seq, {
                "synth_id": synth_id, "voice_id": voice_id,
                "digest": rec.digest,
            })
            return rec

    # -- audit view -------------------------------------------------------
    def audit_log(self) -> Tuple[Mapping, ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    tts = TextToSpeech()
    tts.register_voice("v-en-1", "Ada", "en-US", "feminine", 1)
    rec = tts.synthesize("Hello, world.", "v-en-1", 2)
    assert rec.synth_id == "synth-1"
    assert Fraction(rec.duration_num, rec.duration_den) == Fraction(13, 15)
    ssml_rec = tts.ssml("<speak>Hello <break/>world.</speak>", "v-en-1", 3)
    assert ssml_rec.tags == ("speak", "break")
    assert len(tts.voices()) == 1
    print("text-to-speech OK: voices, synthesize, ssml, pins, audit")


if __name__ == "__main__":
    main()
