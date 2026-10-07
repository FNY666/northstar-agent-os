"""Audio format conversion, loudness normalization, and trimming.

Research note: an *audio processor* maps raw PCM between container formats
(WAV is lossless PCM in RIFF, MP3/AAC/OGG are lossy perceptual codecs, FLAC
is lossless compressed) and edits it -- the load-bearing production
concerns, all kept here:

* **Format registry** -- the container formats this module claims to emit
  are pinned in code (``formats()``); an unknown format name is refused
  fail-closed (``UnknownFormatError``) rather than guessed.
* **Loss ledger** -- each lossy target declares what the codec discards
  (e.g. ``mp3`` drops >16 kHz content and applies perceptual masking);
  the conversion record names the losses so downstream code can refuse
  silently lossy paths. Lossless targets declare no losses.
* **Deterministic normalization** -- peak normalization applies one scalar
  gain ``g = 10^((target_dbfs - peak_dbfs)/20)`` computed over the exact
  int16 PCM samples; identical inputs replay to byte-identical samples
  and digest pins. Gain is rounded per-sample and hard-clipped at full
  scale -- no wrap-around.
* **Exact trimming** -- ms boundaries are converted to sample frames with
  integer arithmetic against the pinned sample rate; out-of-range ranges
  are refused fail-closed, never clamped silently.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is *audio bookkeeping* over a simulated codec set, not
a codec implementation. ``convert()`` pins the declared container
parameters and loss ledger -- it emits no real MP3/OGG/FLAC bytes, cannot
prove a codec would accept the stream, and must be paired with a real
encoder (ffmpeg / libav) for production bytes. ``normalize()`` and
``trim()`` *do* operate on real PCM16 samples byte-for-byte. Loudness is
peak-based, not perceptual (no LUFS/EBU R128 model here).

Version pin: audio-processor.v1
Schema pin: northstar.audio-processor.v1
"""

from __future__ import annotations

import hashlib
import math
import struct
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
AUDIO_PROCESSOR_VERSION = "audio-processor.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.audio-processor.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Largest PCM payload accepted: 64 MiB of raw samples.
MAX_PCM_BYTES = 64 << 20

#: int16 full-scale peak.
FULL_SCALE = 32768

#: Container formats this module claims to emit (simulated codec set).
_FORMATS: FrozenSet[str] = frozenset({"wav", "mp3", "ogg", "flac", "aac", "raw"})

#: Lossless targets: no declared losses on the way in.
_LOSSLESS: FrozenSet[str] = frozenset({"wav", "flac", "raw"})

#: Declared codec losses per lossy target, so callers can audit fidelity.
_LOSSES: Dict[str, Tuple[str, ...]] = {
    "mp3": ("perceptual coding discards masked spectral content",
            "content above ~16 kHz is band-limited away",
            "stereo may be joint-stereo downmixed"),
    "ogg": ("perceptual coding discards masked spectral content",
            "block switching adds pre-echo on transients"),
    "aac": ("perceptual coding discards masked spectral content",
            "intensity stereo discards high-band stereo image"),
}

#: Sample rates this module accepts for registered tracks (Hz).
_VALID_RATES: FrozenSet[int] = frozenset({8000, 16000, 22050, 44100, 48000, 96000})

#: Channel counts this module accepts.
_VALID_CHANNELS: FrozenSet[int] = frozenset({1, 2})


class AudioError(Exception):
    """Base error for audio processing misuse or constraint violations."""


class UnknownTrackError(AudioError):
    """A track id was never registered."""


class DuplicateTrackError(AudioError):
    """A track id is already registered and was never recycled."""


class UnknownFormatError(AudioError):
    """A conversion named a container format this module does not support."""


class AudioTooLargeError(AudioError):
    """PCM payload exceeded MAX_PCM_BYTES."""


class BadRangeError(AudioError):
    """A trim window was negative, empty, or outside the track duration."""


class ValidationError(AudioError):
    """A field failed fail-closed validation."""


class SeqOrderError(AudioError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_format(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("format must be a non-empty str")
    return name.strip().lower()


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _pin_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _peak_dbfs(samples: Tuple[int, ...]) -> float:
    peak = 0
    for s in samples:
        a = -s if s < 0 else s
        if a > peak:
            peak = a
    if peak == 0:
        return float("-inf")
    return 20.0 * math.log10(peak / FULL_SCALE)


@dataclass(frozen=True)
class TrackRecord:
    """A registered PCM track, digest-pinned."""

    track_id: str
    format: str
    sample_rate: int
    channels: int
    bit_depth: int
    frames: int
    duration_ms: int
    pcm_pin: str
    record_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AUDIO_PROCESSOR_VERSION


@dataclass(frozen=True)
class ConversionRecord:
    """A container/format conversion booking, digest-pinned."""

    conversion_id: str
    from_track: str
    to_track: str
    from_format: str
    to_format: str
    sample_rate: int
    channels: int
    losses: Tuple[str, ...]
    record_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AUDIO_PROCESSOR_VERSION


@dataclass(frozen=True)
class NormalizationReport:
    """Peak normalization: gain applied, digest-pinned."""

    normalization_id: str
    from_track: str
    to_track: str
    peak_dbfs: float
    target_dbfs: float
    gain_db: float
    peak_sample: int
    record_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AUDIO_PROCESSOR_VERSION


@dataclass(frozen=True)
class TrimRecord:
    """An exact trim window, digest-pinned."""

    trim_id: str
    from_track: str
    to_track: str
    start_ms: int
    end_ms: int
    start_frame: int
    end_frame: int
    record_pin: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = AUDIO_PROCESSOR_VERSION


class AudioProcessor:
    """WAV/MP3-shaped audio processing bookkeeping, deterministic."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tracks: Dict[str, Tuple[TrackRecord, bytes]] = {}
        self._conversions: Dict[str, ConversionRecord] = {}
        self._normalizations: Dict[str, NormalizationReport] = {}
        self._trims: Dict[str, TrimRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []
        self._last_seq = -1
        self._next_id = 0

    # -- internal ----------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} did not exceed last {self._last_seq}")
        self._last_seq = seq  # failed mutations consume their seq (fail-closed)
        return seq

    def _fresh_id(self, prefix: str) -> str:
        self._next_id += 1
        return f"{prefix}-{self._next_id}"

    def _emit_audit(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        self._audit_events.append(
            {"kind": kind, "seq": seq, "schema": AUDIT_SCHEMA,
             "module": "audio_processor", "detail": dict(detail)}
        )

    def _get_track(self, track_id: Any) -> Tuple[TrackRecord, bytes]:
        if not isinstance(track_id, str) or not track_id:
            raise ValidationError("track_id must be a non-empty str")
        try:
            return self._tracks[track_id]
        except KeyError:
            raise UnknownTrackError(f"unknown track {track_id!r}")

    @staticmethod
    def _decode(pcm: bytes) -> Tuple[int, ...]:
        count = len(pcm) // 2
        return struct.unpack(f"<{count}h", pcm[: count * 2])

    @staticmethod
    def _encode(samples: Tuple[int, ...]) -> bytes:
        return struct.pack(f"<{len(samples)}h", *samples)

    @staticmethod
    def _duration_ms(frames: int, sample_rate: int) -> int:
        return (frames * 1000) // sample_rate

    # -- public API --------------------------------------------------

    def register_track(self, track_id: Any, pcm: Any, sample_rate: Any,
                       channels: Any, seq: Any) -> TrackRecord:
        """Register raw PCM16 mono/stereo samples as a track."""
        with self._lock:
            seq = self._claim_seq(seq)
            if not isinstance(track_id, str) or not track_id:
                raise ValidationError("track_id must be a non-empty str")
            if track_id in self._tracks:
                raise DuplicateTrackError(f"track {track_id!r} already registered")
            if not isinstance(pcm, (bytes, bytearray)) or not pcm:
                raise ValidationError("pcm must be non-empty bytes")
            pcm = bytes(pcm)
            if len(pcm) > MAX_PCM_BYTES:
                raise AudioTooLargeError(f"pcm exceeds {MAX_PCM_BYTES} bytes")
            if len(pcm) % 2 != 0:
                raise ValidationError("pcm16 must have even byte length")
            if isinstance(sample_rate, bool) or sample_rate not in _VALID_RATES:
                raise ValidationError(f"sample_rate must be one of {sorted(_VALID_RATES)}")
            if isinstance(channels, bool) or channels not in _VALID_CHANNELS:
                raise ValidationError(f"channels must be one of {sorted(_VALID_CHANNELS)}")
            frames = len(pcm) // (2 * channels)
            if frames == 0:
                raise ValidationError("pcm holds no complete frames")
            pcm_pin = _pin_bytes(pcm)
            record = TrackRecord(
                track_id=track_id, format="raw", sample_rate=sample_rate,
                channels=channels, bit_depth=16, frames=frames,
                duration_ms=self._duration_ms(frames, sample_rate),
                pcm_pin=pcm_pin,
                record_pin=_pin({
                    "track_id": track_id, "format": "raw",
                    "sample_rate": sample_rate, "channels": channels,
                    "bit_depth": 16, "frames": frames, "pcm_pin": pcm_pin,
                }),
                seq=seq,
            )
            self._tracks[track_id] = (record, pcm)
            self._emit_audit("track-registered", seq, {"track_id": track_id})
            return record

    def formats(self) -> Tuple[str, ...]:
        """Container formats this module claims to emit."""
        return tuple(sorted(_FORMATS))

    def losses(self, to_format: Any) -> Tuple[str, ...]:
        """Declared codec losses for a target format (empty for lossless)."""
        fmt = _check_format(to_format)
        if fmt not in _FORMATS:
            raise UnknownFormatError(f"unknown format {fmt!r}")
        return _LOSSES.get(fmt, ())

    def convert(self, track_id: Any, to_format: Any, seq: Any,
                *, new_id: Optional[Any] = None) -> ConversionRecord:
        """Book a container conversion; emits a new pinned track.

        Simulated: pins declared container parameters and the loss ledger.
        Emits no real codec bytes.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            fmt = _check_format(to_format)
            if fmt not in _FORMATS:
                raise UnknownFormatError(f"unknown format {fmt!r}")
            src, src_pcm = self._get_track(track_id)
            out_id = self._fresh_id("track") if new_id is None else new_id
            if not isinstance(out_id, str) or not out_id:
                raise ValidationError("new_id must be a non-empty str")
            if out_id in self._tracks:
                raise DuplicateTrackError(f"track {out_id!r} already registered")
            record = TrackRecord(
                track_id=out_id, format=fmt, sample_rate=src.sample_rate,
                channels=src.channels, bit_depth=src.bit_depth,
                frames=src.frames, duration_ms=src.duration_ms,
                pcm_pin=src.pcm_pin,
                record_pin=_pin({
                    "track_id": out_id, "format": fmt,
                    "sample_rate": src.sample_rate, "channels": src.channels,
                    "bit_depth": src.bit_depth, "frames": src.frames,
                    "pcm_pin": src.pcm_pin,
                }),
                seq=seq,
            )
            self._tracks[out_id] = (record, src_pcm)
            conversion_id = self._fresh_id("cv")
            conv = ConversionRecord(
                conversion_id=conversion_id,
                from_track=src.track_id, to_track=out_id,
                from_format=src.format, to_format=fmt,
                sample_rate=src.sample_rate, channels=src.channels,
                losses=self.losses(fmt),
                record_pin=_pin({
                    "conversion_id": conversion_id, "from_track": src.track_id,
                    "to_track": out_id, "from_format": src.format,
                    "to_format": fmt, "src_pin": src.record_pin,
                }),
                seq=seq,
            )
            self._conversions[conversion_id] = conv
            self._emit_audit("converted", seq, {
                "conversion_id": conversion_id, "from": src.track_id,
                "to": out_id, "format": fmt,
            })
            return conv

    def normalize(self, track_id: Any, seq: Any, target_dbfs: Any = -1.0,
                  *, new_id: Optional[Any] = None) -> NormalizationReport:
        """Peak-normalize PCM16 samples to target_dbfs (<= 0); hard-clips."""
        with self._lock:
            seq = self._claim_seq(seq)
            if isinstance(target_dbfs, bool) or not isinstance(target_dbfs, (int, float)):
                raise ValidationError("target_dbfs must be a real number, not bool")
            if not math.isfinite(float(target_dbfs)) or float(target_dbfs) > 0.0:
                raise ValidationError("target_dbfs must be finite and <= 0.0")
            src, src_pcm = self._get_track(track_id)
            samples = self._decode(src_pcm)
            peak_dbfs = _peak_dbfs(samples)
            if peak_dbfs == float("-inf"):
                raise ValidationError("cannot normalize silence (peak is -inf dBFS)")
            gain_db = float(target_dbfs) - peak_dbfs
            gain = 10.0 ** (gain_db / 20.0)
            scaled = tuple(
                max(-FULL_SCALE, min(FULL_SCALE - 1, int(round(s * gain))))
                for s in samples
            )
            out_pcm = self._encode(scaled)
            out_id = self._fresh_id("track") if new_id is None else new_id
            if not isinstance(out_id, str) or not out_id:
                raise ValidationError("new_id must be a non-empty str")
            if out_id in self._tracks:
                raise DuplicateTrackError(f"track {out_id!r} already registered")
            pcm_pin = _pin_bytes(out_pcm)
            track_record = TrackRecord(
                track_id=out_id, format=src.format, sample_rate=src.sample_rate,
                channels=src.channels, bit_depth=src.bit_depth,
                frames=src.frames, duration_ms=src.duration_ms,
                pcm_pin=pcm_pin,
                record_pin=_pin({
                    "track_id": out_id, "format": src.format,
                    "sample_rate": src.sample_rate, "channels": src.channels,
                    "bit_depth": src.bit_depth, "frames": src.frames,
                    "pcm_pin": pcm_pin,
                }),
                seq=seq,
            )
            self._tracks[out_id] = (track_record, out_pcm)
            norm_id = self._fresh_id("nm")
            report = NormalizationReport(
                normalization_id=norm_id, from_track=src.track_id,
                to_track=out_id, peak_dbfs=peak_dbfs,
                target_dbfs=float(target_dbfs), gain_db=gain_db,
                peak_sample=max(abs(s) for s in samples),
                record_pin=_pin({
                    "normalization_id": norm_id, "from_track": src.track_id,
                    "to_track": out_id, "peak_dbfs": peak_dbfs,
                    "target_dbfs": float(target_dbfs), "gain_db": gain_db,
                    "pcm_pin": pcm_pin,
                }),
                seq=seq,
            )
            self._normalizations[norm_id] = report
            self._emit_audit("normalized", seq, {
                "normalization_id": norm_id, "from": src.track_id,
                "to": out_id, "target_dbfs": float(target_dbfs),
            })
            return report

    def trim(self, track_id: Any, seq: Any, start_ms: Any, end_ms: Any,
             *, new_id: Optional[Any] = None) -> TrimRecord:
        """Cut [start_ms, end_ms) with integer frame arithmetic."""
        with self._lock:
            seq = self._claim_seq(seq)
            for name, value in (("start_ms", start_ms), ("end_ms", end_ms)):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValidationError(f"{name} must be an int, not bool")
                if value < 0:
                    raise BadRangeError(f"{name} must be non-negative")
            src, src_pcm = self._get_track(track_id)
            if start_ms >= end_ms:
                raise BadRangeError("start_ms must be < end_ms")
            if end_ms > src.duration_ms:
                raise BadRangeError(
                    f"end_ms {end_ms} exceeds duration {src.duration_ms}")
            frame_size = 2 * src.channels
            start_frame = (start_ms * src.sample_rate) // 1000
            end_frame = (end_ms * src.sample_rate) // 1000
            if start_frame >= end_frame:
                raise BadRangeError("window holds no whole frames")
            cut = src_pcm[start_frame * frame_size: end_frame * frame_size]
            out_id = self._fresh_id("track") if new_id is None else new_id
            if not isinstance(out_id, str) or not out_id:
                raise ValidationError("new_id must be a non-empty str")
            if out_id in self._tracks:
                raise DuplicateTrackError(f"track {out_id!r} already registered")
            frames = end_frame - start_frame
            pcm_pin = _pin_bytes(cut)
            track_record = TrackRecord(
                track_id=out_id, format=src.format, sample_rate=src.sample_rate,
                channels=src.channels, bit_depth=src.bit_depth, frames=frames,
                duration_ms=self._duration_ms(frames, src.sample_rate),
                pcm_pin=pcm_pin,
                record_pin=_pin({
                    "track_id": out_id, "format": src.format,
                    "sample_rate": src.sample_rate, "channels": src.channels,
                    "bit_depth": src.bit_depth, "frames": frames,
                    "pcm_pin": pcm_pin,
                }),
                seq=seq,
            )
            self._tracks[out_id] = (track_record, cut)
            trim_id = self._fresh_id("tm")
            rec = TrimRecord(
                trim_id=trim_id, from_track=src.track_id, to_track=out_id,
                start_ms=start_ms, end_ms=end_ms,
                start_frame=start_frame, end_frame=end_frame,
                record_pin=_pin({
                    "trim_id": trim_id, "from_track": src.track_id,
                    "to_track": out_id, "start_frame": start_frame,
                    "end_frame": end_frame, "pcm_pin": pcm_pin,
                }),
                seq=seq,
            )
            self._trims[trim_id] = rec
            self._emit_audit("trimmed", seq, {
                "trim_id": trim_id, "from": src.track_id, "to": out_id,
                "start_ms": start_ms, "end_ms": end_ms,
            })
            return rec

    # -- views -------------------------------------------------------

    def track(self, track_id: Any) -> TrackRecord:
        """Return a track's pinned record."""
        return self._get_track(track_id)[0]

    def pcm(self, track_id: Any) -> bytes:
        """Return a track's raw PCM16 samples."""
        return self._get_track(track_id)[1]

    def track_ids(self) -> Tuple[str, ...]:
        """Registered track ids, insertion order."""
        return tuple(self._tracks)

    def conversion(self, conversion_id: Any) -> ConversionRecord:
        try:
            return self._conversions[conversion_id]
        except KeyError:
            raise UnknownTrackError(f"unknown conversion {conversion_id!r}")

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit_events)


def audio_processor_audit_event(kind: str, seq: int, detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for audio processor events."""
    allowed = {
        "track-registered", "converted", "normalized", "trimmed", "rejected",
    }
    if kind not in allowed:
        raise ValidationError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {"kind": kind, "seq": seq, "schema": AUDIT_SCHEMA,
            "module": "audio_processor", "detail": dict(detail)}


def main() -> None:
    proc = AudioProcessor()
    pcm = struct.pack("<4h", 8192, -8192, 16384, -16384)
    rec = proc.register_track("t1", pcm, 44100, 2, 1)
    assert rec.duration_ms == 1000 // 44100 * 2  # 2 frames at 44.1kHz -> 0ms floor
    conv = proc.convert("t1", "mp3", 2)
    assert conv.losses == proc.losses("mp3")
    report = proc.normalize("t1", 3, -1.0)
    assert report.peak_dbfs < 0.0
    pcm2 = struct.pack("<4h", 1000, -1000, 1000, -1000)
    proc.register_track("t2", pcm2 * 44100, 44100, 1, 4)  # 2s of tone
    tr = proc.trim("t2", 5, 500, 1500)
    assert proc.track(tr.to_track).duration_ms == 1000
    print("audio-processor OK: register, convert, normalize, trim, audit")


if __name__ == "__main__":
    main()
