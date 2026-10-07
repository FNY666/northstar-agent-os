"""Whisper-style speech-to-text interface: transcribe, diarize, language detect.

Research note: a *speech-to-text* service (Whisper/deepgram/AssemblyAI
lineage) turns audio into three products: a time-aligned transcript,
speaker labels per span (diarization), and a language hypothesis with a
probability distribution. The load-bearing production concerns, all kept
here:

* **Audio ledger** -- every clip is registered once with its duration,
  a host-supplied ``sha256:`` digest of the bytes, and the host's
  transcript claim. The clip id is monotonic (``au-N``); duplicate ids
  are refused fail-closed.
* **Deterministic transcript** -- ``transcribe()`` replays the
  registered claim as a digest-pinned ``Transcript`` of time-aligned
  word segments. Timestamps are computed from the claimed text's word
  count spread proportionally over the registered duration; they are a
  rendering of the *claim*, not measured alignments.
* **Deterministic diarization** -- ``diarize()`` assigns speakers to
  fixed-length windows with a seed derived from the audio digest
  (``SPEAKER_00``, ``SPEAKER_01``, ...). Window boundaries never
  overlap; the label count is pinned at registration. This is a
  placeholder for real voice embeddings -- see honest scope.
* **Language distribution** -- ``language()`` replays the host's
  registered probability distribution over BCP 47 codes, pinned to the
  registration; the top code is the primary hypothesis.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this module cannot hear. It books host-reported facts
(transcript text, speaker count, language probabilities) and pins them;
``transcribe()`` proves "the registered claim pins this text", never
"the audio contains these words". Pair with a real ASR engine for
production; keep this as the decision-and-audit layer.

Version pin: speech-to-text.v1
Schema pin: northstar.speech-to-text.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
SPEECH_TO_TEXT_VERSION = "speech-to-text.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.speech-to-text.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Largest audio digest label accepted: sha256 hex only.
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

#: Words per transcript segment (deterministic chunking).
SEGMENT_WORDS = 8

#: Diarization window length, in ms (fixed windows, no overlap).
DIARIZE_WINDOW_MS = 30_000

#: Largest transcript claim accepted, in UTF-8 bytes: 1 MiB.
MAX_TRANSCRIPT_BYTES = 1 << 20


class SpeechToTextError(Exception):
    """Base error for speech-to-text misuse or constraint violations."""


class ValidationError(SpeechToTextError):
    """A field failed fail-closed validation."""


class UnknownAudioError(SpeechToTextError):
    """The named audio id was never registered."""


class DuplicateAudioError(SpeechToTextError):
    """The audio id is already registered (ids are never recycled)."""


class SeqOrderError(SpeechToTextError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _pin(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


@dataclass(frozen=True)
class WordTiming:
    """One word with synthetic start/end offsets in ms."""

    word: str
    start_ms: int
    end_ms: int

    def as_dict(self) -> Dict[str, Any]:
        return {"word": self.word, "start_ms": self.start_ms, "end_ms": self.end_ms}


@dataclass(frozen=True)
class Segment:
    """One transcript segment: text plus start/end ms."""

    index: int
    text: str
    start_ms: int
    end_ms: int
    words: Tuple[WordTiming, ...]
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "text": self.text,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "words": [w.as_dict() for w in self.words],
            "pin": self.pin,
        }


@dataclass(frozen=True)
class Transcript:
    """Digest-pinned time-aligned transcript of a registered clip."""

    transcript_id: str
    audio_id: str
    language_code: str
    task: str
    text: str
    segments: Tuple[Segment, ...]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "transcript_id": self.transcript_id,
            "audio_id": self.audio_id,
            "language_code": self.language_code,
            "task": self.task,
            "text": self.text,
            "segments": [s.as_dict() for s in self.segments],
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class SpeakerSpan:
    """One diarization window with an assigned speaker label."""

    index: int
    speaker: str
    start_ms: int
    end_ms: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "speaker": self.speaker,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
        }


@dataclass(frozen=True)
class Diarization:
    """Digest-pinned speaker labeling of a registered clip."""

    diarization_id: str
    audio_id: str
    speaker_count: int
    spans: Tuple[SpeakerSpan, ...]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "diarization_id": self.diarization_id,
            "audio_id": self.audio_id,
            "speaker_count": self.speaker_count,
            "spans": [s.as_dict() for s in self.spans],
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class LanguageHypothesis:
    """Digest-pinned language distribution of a registered clip."""

    language_id: str
    audio_id: str
    primary_code: str
    probabilities: Tuple[Tuple[str, int], ...]  # (code, per-mille)
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "language_id": self.language_id,
            "audio_id": self.audio_id,
            "primary_code": self.primary_code,
            "probabilities": [[c, p] for c, p in self.probabilities],
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class AudioClip:
    """A registered audio clip: duration, digest, host claims."""

    audio_id: str
    duration_ms: int
    audio_digest: str
    transcript_claim: str
    language_code: str
    language_probs: Tuple[Tuple[str, int], ...]
    speaker_count: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "audio_id": self.audio_id,
            "duration_ms": self.duration_ms,
            "audio_digest": self.audio_digest,
            "transcript_claim": self.transcript_claim,
            "language_code": self.language_code,
            "language_probs": [[c, p] for c, p in self.language_probs],
            "speaker_count": self.speaker_count,
            "seq": self.seq,
            "pin": self.pin,
        }


def _check_audio_id(audio_id: Any) -> str:
    if not isinstance(audio_id, str) or not audio_id.strip():
        raise ValidationError("audio_id must be a non-empty str")
    return audio_id


def _check_digest(digest: Any) -> str:
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        raise ValidationError("audio_digest must be sha256 hex (64 chars)")
    return digest


def _check_language_code(code: Any) -> str:
    if not isinstance(code, str) or not code:
        raise ValidationError("language_code must be a non-empty str")
    if not re.match(r"^[a-z]{2,3}(-[A-Za-z]{2,4})?$", code):
        raise ValidationError("language_code must look like a BCP 47 tag")
    return code


def _check_probs(probs: Any) -> Tuple[Tuple[str, int], ...]:
    if not isinstance(probs, (list, tuple)) or not probs:
        raise ValidationError("language_probs must be a non-empty list")
    out: List[Tuple[str, int]] = []
    seen = set()
    total = 0
    for item in probs:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValidationError("each probability must be a (code, per-mille) pair")
        code, pm = item
        _check_language_code(code)
        if isinstance(pm, bool) or not isinstance(pm, int) or pm < 0:
            raise ValidationError("probability per-mille must be a non-negative int")
        if code in seen:
            raise ValidationError(f"duplicate language code: {code}")
        seen.add(code)
        total += pm
        out.append((code, pm))
    if total != 1000:
        raise ValidationError("language probabilities must sum to 1000 per-mille")
    out.sort(key=lambda p: (-p[1], p[0]))
    if out[0][1] == 0:
        raise ValidationError("primary language probability must be positive")
    return tuple(out)


def _word_timings(text: str, duration_ms: int) -> List[WordTiming]:
    """Spread words proportionally over the duration by char length."""
    words = text.split()
    if not words:
        return []
    weights = [max(len(w), 1) for w in words]
    total = sum(weights)
    timings: List[WordTiming] = []
    cursor = 0
    for i, (w, wt) in enumerate(zip(words, weights)):
        if i == len(words) - 1:
            start, end = cursor, duration_ms
        else:
            start = cursor
            end = cursor + (duration_ms * wt) // total
            end = max(end, start + 1)
        timings.append(WordTiming(word=w, start_ms=start, end_ms=end))
        cursor = end
    return timings


def _segments(timings: List[WordTiming]) -> List[Segment]:
    segs: List[Segment] = []
    for i in range(0, len(timings), SEGMENT_WORDS):
        chunk = timings[i : i + SEGMENT_WORDS]
        text = " ".join(w.word for w in chunk)
        pin = _pin({"index": len(segs), "text": text,
                    "start_ms": chunk[0].start_ms,
                    "end_ms": chunk[-1].end_ms})
        segs.append(
            Segment(
                index=len(segs),
                text=text,
                start_ms=chunk[0].start_ms,
                end_ms=chunk[-1].end_ms,
                words=tuple(chunk),
                pin=pin,
            )
        )
    return segs


def _diarize_spans(duration_ms: int, digest: str, speaker_count: int) -> List[SpeakerSpan]:
    """Deterministic speaker assignment: digest-seeded round of labels."""
    seed = int.from_bytes(hashlib.sha256(digest.encode()).digest()[:8], "big")
    spans: List[SpeakerSpan] = []
    idx = 0
    cursor = 0
    while cursor < duration_ms:
        end = min(cursor + DIARIZE_WINDOW_MS, duration_ms)
        speaker = "SPEAKER_%02d" % ((seed + idx) % speaker_count)
        spans.append(SpeakerSpan(index=idx, speaker=speaker,
                                 start_ms=cursor, end_ms=end))
        cursor = end
        idx += 1
    return spans


class SpeechToText:
    """Whisper-style transcription bookkeeping over registered audio clips."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._clips: Dict[str, AudioClip] = {}
        self._last_seq = -1
        self._transcripts = 0
        self._diarizations = 0
        self._languages = 0
        self._audit: List[Dict[str, Any]] = []

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def register_audio(
        self,
        audio_id: str,
        duration_ms: int,
        audio_digest: str,
        transcript_claim: str,
        seq: int,
        *,
        language_code: str = "en",
        language_probs: Optional[Sequence[Tuple[str, int]]] = None,
        speaker_count: int = 1,
    ) -> AudioClip:
        """Register one audio clip with host-reported claims."""
        with self._lock:
            audio_id = _check_audio_id(audio_id)
            seq = self._next_seq(seq)
            if audio_id in self._clips:
                raise DuplicateAudioError(f"audio already registered: {audio_id}")
            if isinstance(duration_ms, bool) or not isinstance(duration_ms, int):
                raise ValidationError("duration_ms must be an int, not bool")
            if duration_ms <= 0:
                raise ValidationError("duration_ms must be positive")
            audio_digest = _check_digest(audio_digest)
            if not isinstance(transcript_claim, str):
                raise ValidationError("transcript_claim must be a str")
            if len(transcript_claim.encode("utf-8")) > MAX_TRANSCRIPT_BYTES:
                raise ValidationError("transcript_claim exceeds size cap")
            language_code = _check_language_code(language_code)
            if language_probs is None:
                probs = ((language_code, 1000),)
            else:
                probs = _check_probs(language_probs)
                if probs[0][0] != language_code:
                    raise ValidationError(
                        "language_code must be the primary probability"
                    )
            if isinstance(speaker_count, bool) or not isinstance(speaker_count, int):
                raise ValidationError("speaker_count must be an int, not bool")
            if speaker_count < 1:
                raise ValidationError("speaker_count must be >= 1")
            pin = _pin({
                "audio_id": audio_id,
                "duration_ms": duration_ms,
                "audio_digest": audio_digest,
                "transcript_claim": transcript_claim,
                "language_code": language_code,
                "language_probs": [[c, p] for c, p in probs],
                "speaker_count": speaker_count,
            })
            clip = AudioClip(
                audio_id=audio_id,
                duration_ms=duration_ms,
                audio_digest=audio_digest,
                transcript_claim=transcript_claim,
                language_code=language_code,
                language_probs=probs,
                speaker_count=speaker_count,
                seq=seq,
                pin=pin,
            )
            self._clips[audio_id] = clip
            self._audit.append(
                speech_to_text_audit_event("registered", seq, audio_id)
            )
            return clip

    def clip(self, audio_id: str) -> AudioClip:
        with self._lock:
            if audio_id not in self._clips:
                raise UnknownAudioError(f"unknown audio: {audio_id}")
            return self._clips[audio_id]

    def audio_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._clips))

    def transcribe(
        self,
        audio_id: str,
        seq: int,
        *,
        task: str = "transcribe",
    ) -> Transcript:
        """Emit the digest-pinned time-aligned transcript of a clip."""
        with self._lock:
            seq = self._next_seq(seq)
            if audio_id not in self._clips:
                raise UnknownAudioError(f"unknown audio: {audio_id}")
            if task not in ("transcribe", "translate"):
                raise ValidationError('task must be "transcribe" or "translate"')
            clip = self._clips[audio_id]
            timings = _word_timings(clip.transcript_claim, clip.duration_ms)
            segs = _segments(timings)
            self._transcripts += 1
            tid = f"tr-{self._transcripts}"
            pin = _pin({
                "transcript_id": tid,
                "audio_id": audio_id,
                "language_code": clip.language_code,
                "task": task,
                "text": clip.transcript_claim,
                "segments": [s.as_dict() for s in segs],
                "clip_pin": clip.pin,
            })
            rec = Transcript(
                transcript_id=tid,
                audio_id=audio_id,
                language_code=clip.language_code,
                task=task,
                text=clip.transcript_claim,
                segments=tuple(segs),
                seq=seq,
                pin=pin,
            )
            self._audit.append(
                speech_to_text_audit_event("transcribed", seq, audio_id)
            )
            return rec

    def diarize(self, audio_id: str, seq: int) -> Diarization:
        """Emit deterministic speaker labeling of a clip's duration."""
        with self._lock:
            seq = self._next_seq(seq)
            if audio_id not in self._clips:
                raise UnknownAudioError(f"unknown audio: {audio_id}")
            clip = self._clips[audio_id]
            spans = _diarize_spans(
                clip.duration_ms, clip.audio_digest, clip.speaker_count
            )
            self._diarizations += 1
            did = f"dz-{self._diarizations}"
            pin = _pin({
                "diarization_id": did,
                "audio_id": audio_id,
                "speaker_count": clip.speaker_count,
                "spans": [s.as_dict() for s in spans],
                "clip_pin": clip.pin,
            })
            rec = Diarization(
                diarization_id=did,
                audio_id=audio_id,
                speaker_count=clip.speaker_count,
                spans=tuple(spans),
                seq=seq,
                pin=pin,
            )
            self._audit.append(
                speech_to_text_audit_event("diarized", seq, audio_id)
            )
            return rec

    def language(self, audio_id: str, seq: int) -> LanguageHypothesis:
        """Emit the pinned language distribution of a clip."""
        with self._lock:
            seq = self._next_seq(seq)
            if audio_id not in self._clips:
                raise UnknownAudioError(f"unknown audio: {audio_id}")
            clip = self._clips[audio_id]
            self._languages += 1
            lid = f"lg-{self._languages}"
            pin = _pin({
                "language_id": lid,
                "audio_id": audio_id,
                "primary_code": clip.language_probs[0][0],
                "probabilities": [[c, p] for c, p in clip.language_probs],
                "clip_pin": clip.pin,
            })
            rec = LanguageHypothesis(
                language_id=lid,
                audio_id=audio_id,
                primary_code=clip.language_probs[0][0],
                probabilities=clip.language_probs,
                seq=seq,
                pin=pin,
            )
            self._audit.append(
                speech_to_text_audit_event("language-detected", seq, audio_id)
            )
            return rec

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def speech_to_text_audit_event(kind: str, seq: int, audio_id: str) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids, never claims)."""
    if kind not in (
        "registered",
        "transcribed",
        "diarized",
        "language-detected",
        "rejected",
    ):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    _check_audio_id(audio_id)
    return {
        "kind": kind,
        "seq": seq,
        "audio_id": audio_id,
        "module": "speech-to-text",
        "version": SPEECH_TO_TEXT_VERSION,
        "schema": AUDIT_SCHEMA,
    }


def main() -> None:
    stt = SpeechToText()
    digest = "ab" * 32
    stt.register_audio(
        "meeting-1", 120_000, digest,
        "hello world this is a deterministic test of the transcript pipeline",
        1, language_code="en",
        language_probs=[("en", 950), ("es", 50)], speaker_count=2,
    )
    tr = stt.transcribe("meeting-1", 2)
    dz = stt.diarize("meeting-1", 3)
    lg = stt.language("meeting-1", 4)
    assert tr.text.startswith("hello world")
    assert tr.segments and tr.segments[0].start_ms == 0
    assert dz.spans and dz.spans[0].speaker.startswith("SPEAKER_")
    assert lg.primary_code == "en"
    print("speech-to-text OK: register, transcribe, diarize, language")


if __name__ == "__main__":
    main()
