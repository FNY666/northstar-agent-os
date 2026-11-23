"""FFmpeg-style video transcode bookkeeping, in-memory.

Research note: a *transcoder* (ffmpeg is the reference) maps an input
media stream through a codec pipeline into a different codec/container --
the load-bearing production concerns, all kept here:

* **Codec/profile registry** -- supported codecs and output profiles are
  pinned in code and listed by ``codecs()`` / ``profiles()``; an unknown
  codec name is refused fail-closed (``UnknownCodecError``) rather than
  guessed.
* **Deterministic planning** -- every transcode plan is a pure function
  of (source pin, target codec, profile); identical inputs replay to
  byte-identical output descriptors and digest pins.
* **Pins, not claims** -- each record carries a ``sha256:`` pin over the
  canonical input triple, so a tampered plan no longer verifies. The pin
  proves internal consistency, never that the media decodes correctly.
* **Loss ledger** -- every transcode declares what it drops (re-encode
  generation loss, downscale detail loss, audio-only track drop); the
  record names the losses so callers can refuse silently lossy paths.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is a *structural bookkeeping* interface over a
simulated planner, not a media pipeline. ``probe()`` pins host-reported
media metadata (it cannot read a real file, cannot verify the codec is
truthful); ``transcode()`` emits a deterministic output *descriptor*,
never media bytes; ``thumbnail()`` plans a capture, it extracts no
pixels. Real deployments hand the pinned source to ffmpeg itself and
record its output digest here.

Version pin: video-transcoder.v1
Schema pin: northstar.video-transcoder.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
VIDEO_TRANSCODER_VERSION = "video-transcoder.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.video-transcoder.v1"

#: Largest accepted source duration: 7 days in ms.
MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1000

#: Bounds for source dimensions (a probe asserts geometry, never reads pixels).
MIN_DIMENSION = 1
MAX_DIMENSION = 16384

#: Bounds for probe fps.
MAX_FPS = 240.0

#: Thumbnail height in px; width follows the source aspect ratio.
THUMB_HEIGHT = 180

#: Pinned video codecs this module claims to plan for.
_VIDEO_CODECS: FrozenSet[str] = frozenset(
    {"h264", "h265", "vp9", "av1", "vp8", "mpeg4", "mpeg2", "theora", "prores"}
)

#: Pinned audio codecs (used for audio-only profiles and audio tracks).
_AUDIO_CODECS: FrozenSet[str] = frozenset({"aac", "mp3", "opus", "flac", "vorbis"})

#: All pinned codecs.
_CODECS: FrozenSet[str] = _VIDEO_CODECS | _AUDIO_CODECS

#: Pinned containers this module claims to plan for.
_CONTAINERS: FrozenSet[str] = frozenset(
    {"mp4", "mkv", "webm", "mov", "avi", "flv", "ts", "m4a", "mp3", "ogg", "wav", "flac"}
)

#: Pinned thumbnail formats.
_THUMB_FORMATS: FrozenSet[str] = frozenset({"jpeg", "png", "webp"})

#: Output profiles: name -> (width, height, bitrate_kbps). ``None`` dims means
#: audio-only (no video track planned).
_PROFILES: Dict[str, Tuple[Optional[int], Optional[int], int]] = {
    "uhd": (3840, 2160, 16000),
    "fullhd": (1920, 1080, 6000),
    "hd": (1280, 720, 2800),
    "sd": (854, 480, 1200),
    "ld": (640, 360, 600),
    "audio-only": (None, None, 128),
}

#: Declared losses per (source codec, target codec) pair.
_LOSSES: Dict[Tuple[str, str], Tuple[str, ...]] = {}


def _losses_for(src_codec: str, dst_codec: str, downscale: bool, upscale: bool) -> Tuple[str, ...]:
    losses = list(_LOSSES.get((src_codec, dst_codec), ()))
    if src_codec == dst_codec:
        losses.append("re-encode generation loss (same codec)")
    else:
        losses.append("re-encode generation loss (codec change)")
    if downscale:
        losses.append("downscale detail loss below native resolution")
    if upscale:
        losses.append("upscale adds no detail; banding risk")
    if (src_codec, dst_codec) in (("av1", "h264"), ("h265", "h264"), ("vp9", "h264")):
        losses.append("higher compression efficiency lost")
    return tuple(losses)


class VideoTranscoderError(Exception):
    """Base error for transcode misuse or constraint violations."""


class UnknownCodecError(VideoTranscoderError):
    """A codec this module does not know was named."""


class UnknownContainerError(VideoTranscoderError):
    """A container this module does not know was named."""


class UnknownProfileError(VideoTranscoderError):
    """An output profile this module does not know was named."""


class UnknownSourceError(VideoTranscoderError):
    """The referenced probed source is not registered."""


class NoOpTranscodeError(VideoTranscoderError):
    """Target codec and profile match the source; nothing would change."""


class BadMediaSpecError(VideoTranscoderError):
    """Host-reported media metadata failed fail-closed validation."""


class ValidationError(VideoTranscoderError):
    """A field failed fail-closed validation."""


class SeqOrderError(VideoTranscoderError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_codec(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("codec must be a non-empty str")
    codec = name.strip().lower()
    if codec not in _CODECS:
        raise UnknownCodecError(f"unknown codec: {codec}")
    return codec


def _check_container(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("container must be a non-empty str")
    container = name.strip().lower()
    if container not in _CONTAINERS:
        raise UnknownContainerError(f"unknown container: {container}")
    return container


def _check_profile(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("profile must be a non-empty str")
    profile = name.strip().lower()
    if profile not in _PROFILES:
        raise UnknownProfileError(f"unknown profile: {profile}")
    return profile


def _check_dim(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadMediaSpecError(f"{field} must be an int, not bool")
    if not (MIN_DIMENSION <= value <= MAX_DIMENSION):
        raise BadMediaSpecError(
            f"{field} must be within [{MIN_DIMENSION}, {MAX_DIMENSION}]"
        )
    return value


def _check_duration(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadMediaSpecError("duration_ms must be an int, not bool")
    if not (1 <= value <= MAX_DURATION_MS):
        raise BadMediaSpecError(
            f"duration_ms must be within [1, {MAX_DURATION_MS}]"
        )
    return value


def _check_fps(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadMediaSpecError("fps must be a number, not bool")
    fps = float(value)
    if not (0.0 < fps <= MAX_FPS) or fps != fps or fps in (float("inf"), float("-inf")):
        raise BadMediaSpecError(f"fps must be finite and within (0, {MAX_FPS}]")
    return fps


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MediaInfo:
    """Pinned host-reported media metadata from a simulated probe."""

    info_id: str
    source_digest: str
    codec: str
    container: str
    width: int
    height: int
    duration_ms: int
    fps: float
    audio_codec: Optional[str]
    bitrate_kbps: Optional[int]
    seq: int
    version: str = VIDEO_TRANSCODER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "info_id": self.info_id,
            "source_digest": self.source_digest,
            "codec": self.codec,
            "container": self.container,
            "width": self.width,
            "height": self.height,
            "duration_ms": self.duration_ms,
            "fps": self.fps,
            "audio_codec": self.audio_codec,
            "bitrate_kbps": self.bitrate_kbps,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TranscodeJob:
    """One pinned transcode plan: inputs, deterministic output descriptor pin."""

    job_id: str
    source_id: str
    source_digest: str
    target_codec: str
    target_profile: str
    out_width: Optional[int]
    out_height: Optional[int]
    out_bitrate_kbps: int
    estimated_size_kb: int
    losses: Tuple[str, ...]
    output_digest: str
    seq: int
    version: str = VIDEO_TRANSCODER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "source_id": self.source_id,
            "source_digest": self.source_digest,
            "target_codec": self.target_codec,
            "target_profile": self.target_profile,
            "out_width": self.out_width,
            "out_height": self.out_height,
            "out_bitrate_kbps": self.out_bitrate_kbps,
            "estimated_size_kb": self.estimated_size_kb,
            "losses": list(self.losses),
            "output_digest": self.output_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self, output_descriptor: Mapping[str, Any]) -> bool:
        """Re-derive the output pin for a candidate output descriptor."""
        return _pin({"output": dict(output_descriptor)}) == self.output_digest


@dataclass(frozen=True)
class ThumbnailRecord:
    """One pinned thumbnail capture plan (no pixels extracted)."""

    thumb_id: str
    source_id: str
    source_digest: str
    at_ms: int
    width: int
    height: int
    format: str
    thumb_digest: str
    seq: int
    version: str = VIDEO_TRANSCODER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "thumb_id": self.thumb_id,
            "source_id": self.source_id,
            "source_digest": self.source_digest,
            "at_ms": self.at_ms,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "thumb_digest": self.thumb_digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Transcoder
# ---------------------------------------------------------------------------


class VideoTranscoder:
    """FFmpeg-style transcode planning bookkeeping, in-memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._counter = 0
        self._sources: Dict[str, MediaInfo] = {}
        self._jobs: Dict[str, TranscodeJob] = {}
        self._thumbs: Dict[str, ThumbnailRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    # -- registry ------------------------------------------------------

    def codecs(self) -> List[str]:
        """List pinned codecs."""
        return sorted(_CODECS)

    def profiles(self) -> Dict[str, Dict[str, Any]]:
        """List pinned output profiles with their target geometry."""
        return {
            name: {
                "width": dims[0],
                "height": dims[1],
                "bitrate_kbps": dims[2],
            }
            for name, dims in sorted(_PROFILES.items())
        }

    # -- probe ---------------------------------------------------------

    def probe(self, source_meta: Mapping[str, Any], seq: int) -> MediaInfo:
        """Pin host-reported media metadata as a simulated probe result."""
        with self._lock:
            seq = self._advance(seq)
            if not isinstance(source_meta, Mapping):
                raise BadMediaSpecError("source_meta must be a mapping")
            meta = dict(source_meta)
            try:
                jcs_canonical_json(meta)
            except (TypeError, ValueError) as exc:
                raise BadMediaSpecError(
                    f"source_meta is not canonicalizable: {exc}"
                ) from exc
            codec = _check_codec(meta.get("codec"))
            container = _check_container(meta.get("container"))
            width = _check_dim(meta.get("width"), "width")
            height = _check_dim(meta.get("height"), "height")
            duration_ms = _check_duration(meta.get("duration_ms"))
            fps = _check_fps(meta.get("fps"))
            audio_codec = meta.get("audio_codec")
            if audio_codec is not None:
                audio_codec = _check_codec(audio_codec)
            bitrate_kbps = meta.get("bitrate_kbps")
            if bitrate_kbps is not None:
                if isinstance(bitrate_kbps, bool) or not isinstance(bitrate_kbps, int):
                    raise BadMediaSpecError("bitrate_kbps must be an int, not bool")
                if bitrate_kbps <= 0:
                    raise BadMediaSpecError("bitrate_kbps must be positive")

            info_id = self._next_id("info")
            record = MediaInfo(
                info_id=info_id,
                source_digest=_pin({"source": meta}),
                codec=codec,
                container=container,
                width=width,
                height=height,
                duration_ms=duration_ms,
                fps=fps,
                audio_codec=audio_codec,
                bitrate_kbps=bitrate_kbps,
                seq=seq,
            )
            self._sources[info_id] = record
            self._audit.append(video_transcoder_audit_event("probed", seq, info_id))
            return record

    def source(self, info_id: str) -> MediaInfo:
        """Look up a probed source by id."""
        if not isinstance(info_id, str) or not info_id:
            raise ValidationError("info_id must be a non-empty str")
        with self._lock:
            try:
                return self._sources[info_id]
            except KeyError:
                raise UnknownSourceError(f"unknown source: {info_id}") from None

    # -- transcode -----------------------------------------------------

    def transcode(
        self, source_id: str, target_codec: str, profile: str, seq: int
    ) -> Tuple[TranscodeJob, Dict[str, Any]]:
        """Plan a transcode; returns (job record, output descriptor)."""
        with self._lock:
            seq = self._advance(seq)
            src = self.source(source_id)
            target_codec = _check_codec(target_codec)
            profile = _check_profile(profile)
            out_width, out_height, out_bitrate = _PROFILES[profile]

            if target_codec == src.codec and profile != "audio-only":
                if (
                    out_width == src.width
                    and out_height == src.height
                ):
                    raise NoOpTranscodeError(
                        "target codec and geometry match the source; nothing would change"
                    )

            if target_codec in _AUDIO_CODECS and profile != "audio-only":
                raise ValidationError(
                    "audio codecs require the audio-only profile"
                )
            if profile == "audio-only" and target_codec not in _AUDIO_CODECS:
                raise ValidationError(
                    "the audio-only profile requires an audio codec"
                )

            downscale = (
                out_width is not None
                and (out_width < src.width or out_height < src.height)  # type: ignore[operator]
            )
            upscale = (
                out_width is not None
                and (out_width > src.width or out_height > src.height)  # type: ignore[operator]
            )
            losses = _losses_for(src.codec, target_codec, bool(downscale), bool(upscale))
            if profile == "audio-only":
                losses = losses + ("video track dropped",)

            # Exact integer estimate: duration_ms/1000 * kbps / 8 = KB.
            estimated_size_kb = (src.duration_ms * out_bitrate) // 8000

            output_descriptor: Dict[str, Any] = {
                "codec": target_codec,
                "profile": profile,
                "width": out_width,
                "height": out_height,
                "bitrate_kbps": out_bitrate,
                "duration_ms": src.duration_ms,
                "estimated_size_kb": estimated_size_kb,
            }
            job_id = self._next_id("job")
            record = TranscodeJob(
                job_id=job_id,
                source_id=src.info_id,
                source_digest=src.source_digest,
                target_codec=target_codec,
                target_profile=profile,
                out_width=out_width,
                out_height=out_height,
                out_bitrate_kbps=out_bitrate,
                estimated_size_kb=estimated_size_kb,
                losses=losses,
                output_digest=_pin({"output": output_descriptor}),
                seq=seq,
            )
            self._jobs[job_id] = record
            self._audit.append(video_transcoder_audit_event("transcoded", seq, job_id))
            return record, output_descriptor

    def job(self, job_id: str) -> TranscodeJob:
        """Look up a transcode job by id."""
        if not isinstance(job_id, str) or not job_id:
            raise ValidationError("job_id must be a non-empty str")
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError:
                raise ValidationError(f"unknown job_id: {job_id}") from None

    # -- thumbnail -----------------------------------------------------

    def thumbnail(
        self, source_id: str, at_ms: int, seq: int, format: str = "jpeg"
    ) -> ThumbnailRecord:
        """Plan a thumbnail capture at a timestamp within the source."""
        with self._lock:
            seq = self._advance(seq)
            src = self.source(source_id)
            if isinstance(at_ms, bool) or not isinstance(at_ms, int):
                raise ValidationError("at_ms must be an int, not bool")
            if not (0 <= at_ms <= src.duration_ms):
                raise ValidationError(
                    f"at_ms must be within [0, {src.duration_ms}]"
                )
            if not isinstance(format, str) or format.strip().lower() not in _THUMB_FORMATS:
                raise ValidationError(
                    f"format must be one of {sorted(_THUMB_FORMATS)}"
                )
            fmt = format.strip().lower()
            # Width follows source aspect; height pinned at THUMB_HEIGHT.
            width = max(16, round(THUMB_HEIGHT * src.width / src.height))
            thumb_id = self._next_id("thumb")
            record = ThumbnailRecord(
                thumb_id=thumb_id,
                source_id=src.info_id,
                source_digest=src.source_digest,
                at_ms=at_ms,
                width=width,
                height=THUMB_HEIGHT,
                format=fmt,
                thumb_digest=_pin(
                    {
                        "source": src.source_digest,
                        "at_ms": at_ms,
                        "width": width,
                        "height": THUMB_HEIGHT,
                        "format": fmt,
                    }
                ),
                seq=seq,
            )
            self._thumbs[thumb_id] = record
            self._audit.append(
                video_transcoder_audit_event("thumbnail-captured", seq, thumb_id)
            )
            return record

    # -- audit ---------------------------------------------------------

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def video_transcoder_audit_event(
    kind: str, seq: int, record_id: str
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids/digests only)."""
    if kind not in ("probed", "transcoded", "thumbnail-captured", "rejected"):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    if not isinstance(record_id, str):
        raise ValidationError("record_id must be a str")
    return {
        "kind": kind,
        "seq": seq,
        "record_id": record_id,
        "module": "video-transcoder",
        "version": VIDEO_TRANSCODER_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    vt = VideoTranscoder()
    info = vt.probe(
        {
            "codec": "h264",
            "container": "mp4",
            "width": 1920,
            "height": 1080,
            "duration_ms": 60_000,
            "fps": 30,
            "audio_codec": "aac",
            "bitrate_kbps": 8000,
        },
        1,
    )
    assert info.info_id == "info-1"
    job, out = vt.transcode(info.info_id, "h265", "hd", 2)
    assert job.verify(out)
    assert out["width"] == 1280 and out["estimated_size_kb"] == 60 * 2800 // 8
    assert any("downscale" in loss for loss in job.losses)
    thumb = vt.thumbnail(info.info_id, 30_000, 3)
    assert thumb.width == 320 and thumb.height == 180
    print("video-transcoder OK: probe, transcode, thumbnail, pins, audit")


if __name__ == "__main__":
    main()
