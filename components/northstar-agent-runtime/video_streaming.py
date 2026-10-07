"""HLS/DASH adaptive-bitrate streaming bookkeeping, in-memory.

Research note: HTTP Live Streaming (Apple, RFC 8216) and MPEG-DASH
(ISO/IEC 23009-1) are the two dominant adaptive-bitrate protocols. The
load-bearing production concerns, all kept here:

* **Manifest vocabulary** -- ``format`` is pinned to ``hls`` / ``dash``;
  anything else is refused fail-closed (``BadFormatError``).
* **Deterministic rendering** -- a manifest is a pure function of
  (asset tracks, format, DRM binding); identical inputs replay to
  byte-identical playlist/MPD text and digest pins across instances.
* **Pins, not claims** -- every record carries a ``sha256:`` pin over its
  canonical body, so a tampered playlist no longer verifies. The pin
  proves internal consistency, never that a CDN serves the bytes.
* **Segment lattice** -- ``segment()`` books one frozen ``SegmentRecord``
  per (track, index); indices outside ``ceil(duration/segment_ms)``
  are refused fail-closed. Byte ranges are derived from the pinned
  bitrate, never measured.
* **DRM signalling** -- ``drm()`` books a key binding (Widevine /
  Fairplay / PlayReady / ClearKey) with a deterministically derived
  ``key_id``; key *material* never enters a record. ``manifest()`` can
  pin the binding, emitting ``#EXT-X-KEY`` (HLS) or ``ContentProtection``
  (DASH).
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock. Failed
  mutations consume their seq (fail-closed ledger position).

Honest scope: this is a *structural bookkeeping* interface over
simulated packagers, not a media pipeline. ``register_asset()`` pins
host-reported track metadata (it cannot read a real file); ``manifest()``
renders playlist text, it runs no packager; ``segment()`` plans segment
URIs and byte ranges, it writes no media bytes; ``drm()`` derives a
placeholder ``key_id`` and PSSH blob -- a production deployment gets
them from a real license server. Real deployments hand the pinned
asset to a packager (e.g. Shaka Packager) and record its output
digests here.

Version pin: video-streaming.v1
Schema pin: northstar.video-streaming.v1
"""

from __future__ import annotations

import base64
import hashlib
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
VIDEO_STREAMING_VERSION = "video-streaming.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.video-streaming.v1"

#: Largest accepted asset duration: 7 days in ms.
MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1000

#: HLS media segment target duration (RFC 8216 common choice).
HLS_SEGMENT_MS = 6000

#: DASH segment duration used in SegmentTemplate.
DASH_SEGMENT_MS = 4000

#: Bounds for track dimensions.
MIN_DIMENSION = 16
MAX_DIMENSION = 16384

#: Bounds for bitrate (kbps).
MIN_BITRATE_KBPS = 8
MAX_BITRATE_KBPS = 200_000

#: Bounds for audio channels.
MIN_CHANNELS = 1
MAX_CHANNELS = 16

#: Bounds for fps.
MAX_FPS = 240.0

#: Pinned manifest formats.
_FORMATS: FrozenSet[str] = frozenset({"hls", "dash"})

#: Pinned track kinds.
_KINDS: FrozenSet[str] = frozenset({"video", "audio"})

#: Pinned codecs this module claims to plan for.
_CODECS: FrozenSet[str] = frozenset(
    {"h264", "h265", "vp9", "av1", "aac", "mp3", "opus", "ac3", "eac3"}
)

#: HLS CODECS attribute per codec (representative sample entries).
_HLS_CODEC_ATTRS: Dict[str, str] = {
    "h264": "avc1.64001f",
    "h265": "hvc1.1.6.L93.B0",
    "vp9": "vp09.00.10.08",
    "av1": "av01.0.05M.08",
    "aac": "mp4a.40.2",
    "mp3": "mp4a.69",
    "opus": "Opus",
    "ac3": "ac-3",
    "eac3": "ec-3",
}

#: Pinned DRM systems.
_DRM_SYSTEMS: FrozenSet[str] = frozenset(
    {"widevine", "fairplay", "playready", "clearkey"}
)

#: DASH ContentProtection schemeIdUri per DRM system.
_DRM_SCHEME_URIS: Dict[str, str] = {
    "widevine": "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
    "playready": "urn:uuid:9a04f079-9840-4286-ab92-34bf9b2fc53c",
    "fairplay": "urn:uuid:94ce86fb-07ff-4f43-adb8-93d2fa968ca2",
    "clearkey": "urn:uuid:e2719d58-a985-b3c9-781a-b030af78d30e",
}

#: HLS EXT-X-KEY (METHOD, KEYFORMAT) per DRM system.
_HLS_KEY_METHODS: Dict[str, Tuple[str, str]] = {
    "fairplay": ("SAMPLE-AES", "com.apple.streamingkeydelivery"),
    "widevine": ("SAMPLE-AES-CTR", "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
    "playready": ("SAMPLE-AES-CTR", "urn:uuid:9a04f079-9840-4286-ab92-34bf9b2fc53c"),
    "clearkey": ("SAMPLE-AES-CTR", "urn:uuid:e2719d58-a985-b3c9-781a-b030af78d30e"),
}

#: Default constructor seed (domain separator for key derivation).
_DEFAULT_SEED = b"video-streaming.v1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VideoStreamingError(Exception):
    """Base error for the video_streaming module."""


class ValidationError(VideoStreamingError):
    """A value failed structural validation."""


class UnknownAssetError(VideoStreamingError):
    """No asset with that id is registered."""


class UnknownManifestError(VideoStreamingError):
    """No manifest with that id exists."""


class UnknownSegmentError(VideoStreamingError):
    """No segment with that id exists."""


class UnknownDRMError(VideoStreamingError):
    """No DRM binding with that id exists."""


class DuplicateAssetError(VideoStreamingError):
    """An asset with that id is already registered."""


class DuplicateDRMError(VideoStreamingError):
    """A DRM binding for that asset+system already exists."""


class BadFormatError(VideoStreamingError):
    """The manifest format is not in the pinned vocabulary."""


class BadTrackError(VideoStreamingError):
    """A track spec failed validation."""


class BadDurationError(VideoStreamingError):
    """The asset duration is out of bounds."""


class OutOfRangeError(VideoStreamingError):
    """A track index or segment index is outside the asset lattice."""


class UnknownCodecError(VideoStreamingError):
    """The codec is not in the pinned vocabulary."""


class SeqOrderError(VideoStreamingError):
    """The caller-supplied seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_asset_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("asset_id must be a non-empty str")
    return value.strip()


def _check_format(value: Any) -> str:
    if not isinstance(value, str):
        raise BadFormatError("format must be a str")
    fmt = value.strip().lower()
    if fmt not in _FORMATS:
        raise BadFormatError(f"unknown format: {fmt!r}; pinned: {sorted(_FORMATS)}")
    return fmt


def _check_codec(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnknownCodecError("codec must be a non-empty str")
    codec = value.strip().lower()
    if codec not in _CODECS:
        raise UnknownCodecError(f"unknown codec: {codec!r}; pinned: {sorted(_CODECS)}")
    return codec


def _check_bitrate(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTrackError("bitrate_kbps must be an int, not bool")
    if not (MIN_BITRATE_KBPS <= value <= MAX_BITRATE_KBPS):
        raise BadTrackError(
            f"bitrate_kbps must be within [{MIN_BITRATE_KBPS}, {MAX_BITRATE_KBPS}]"
        )
    return value


def _check_duration_ms(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadDurationError("duration_ms must be an int, not bool")
    if not (1 <= value <= MAX_DURATION_MS):
        raise BadDurationError(f"duration_ms must be within [1, {MAX_DURATION_MS}]")
    return value


def _check_drm_system(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("drm system must be a str")
    system = value.strip().lower()
    if system not in _DRM_SYSTEMS:
        raise ValidationError(
            f"unknown drm system: {system!r}; pinned: {sorted(_DRM_SYSTEMS)}"
        )
    return system


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrackSpec:
    """One rendition track: video (codec, geometry, fps) or audio."""

    kind: str
    codec: str
    bitrate_kbps: int
    width: Optional[int] = None
    height: Optional[int] = None
    fps: Optional[float] = None
    channels: Optional[int] = None
    language: str = "und"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "codec": self.codec,
            "bitrate_kbps": self.bitrate_kbps,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "channels": self.channels,
            "language": self.language,
        }

    def hls_codec_attr(self) -> str:
        return _HLS_CODEC_ATTRS[self.codec]


def _check_track(spec: Any) -> TrackSpec:
    if not isinstance(spec, Mapping):
        raise BadTrackError("track must be a mapping")
    kind = spec.get("kind")
    if not isinstance(kind, str) or kind.strip().lower() not in _KINDS:
        raise BadTrackError(f"track kind must be one of {sorted(_KINDS)}")
    kind = kind.strip().lower()
    codec = _check_codec(spec.get("codec"))
    bitrate_kbps = _check_bitrate(spec.get("bitrate_kbps"))
    if kind == "video":
        width = spec.get("width")
        height = spec.get("height")
        if isinstance(width, bool) or not isinstance(width, int):
            raise BadTrackError("video track width must be an int, not bool")
        if isinstance(height, bool) or not isinstance(height, int):
            raise BadTrackError("video track height must be an int, not bool")
        if not (MIN_DIMENSION <= width <= MAX_DIMENSION):
            raise BadTrackError("video track width out of bounds")
        if not (MIN_DIMENSION <= height <= MAX_DIMENSION):
            raise BadTrackError("video track height out of bounds")
        fps = spec.get("fps", 30.0)
        if isinstance(fps, bool) or not isinstance(fps, (int, float)):
            raise BadTrackError("fps must be a number, not bool")
        fps = float(fps)
        if not (0.0 < fps <= MAX_FPS) or fps != fps:
            raise BadTrackError("fps must be finite and within (0, 240]")
        return TrackSpec(
            kind="video",
            codec=codec,
            bitrate_kbps=bitrate_kbps,
            width=width,
            height=height,
            fps=fps,
        )
    channels = spec.get("channels", 2)
    if isinstance(channels, bool) or not isinstance(channels, int):
        raise BadTrackError("audio track channels must be an int, not bool")
    if not (MIN_CHANNELS <= channels <= MAX_CHANNELS):
        raise BadTrackError("audio track channels out of bounds")
    language = spec.get("language", "und")
    if not isinstance(language, str) or not language.strip():
        raise BadTrackError("audio track language must be a non-empty str")
    return TrackSpec(
        kind="audio",
        codec=codec,
        bitrate_kbps=bitrate_kbps,
        channels=channels,
        language=language.strip().lower(),
    )


@dataclass(frozen=True)
class AssetRecord:
    """A registered source asset with its rendition ladder."""

    asset_id: str
    duration_ms: int
    tracks: Tuple[TrackSpec, ...]
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            [
                "asset",
                self.asset_id,
                self.duration_ms,
                [t.as_dict() for t in self.tracks],
            ]
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "duration_ms": self.duration_ms,
            "tracks": [t.as_dict() for t in self.tracks],
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ManifestRecord:
    """A rendered master manifest (HLS multivariant or DASH MPD), or an
    HLS per-track media playlist when kind == "media"."""

    manifest_id: str
    asset_id: str
    format: str
    kind: str
    track_index: Optional[int]
    text: str
    drm_id: Optional[str]
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            [
                "manifest",
                self.asset_id,
                self.format,
                self.kind,
                self.track_index,
                self.text,
                self.drm_id,
            ]
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "asset_id": self.asset_id,
            "format": self.format,
            "kind": self.kind,
            "track_index": self.track_index,
            "text": self.text,
            "drm_id": self.drm_id,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SegmentRecord:
    """One planned media segment in the (track, index) lattice."""

    segment_id: str
    asset_id: str
    track_index: int
    segment_index: int
    uri: str
    duration_ms: int
    start_byte: int
    end_byte: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            [
                "segment",
                self.asset_id,
                self.track_index,
                self.segment_index,
                self.uri,
                self.duration_ms,
                self.start_byte,
                self.end_byte,
            ]
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "segment_id": self.segment_id,
            "asset_id": self.asset_id,
            "track_index": self.track_index,
            "segment_index": self.segment_index,
            "uri": self.uri,
            "duration_ms": self.duration_ms,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DRMRecord:
    """A DRM key binding for an asset (simulated key_id + PSSH)."""

    drm_id: str
    asset_id: str
    system: str
    key_id: str
    license_url: str
    pssh_b64: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            [
                "drm",
                self.asset_id,
                self.system,
                self.key_id,
                self.license_url,
                self.pssh_b64,
            ]
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "drm_id": self.drm_id,
            "asset_id": self.asset_id,
            "system": self.system,
            "key_id": self.key_id,
            "license_url": self.license_url,
            "pssh_b64": self.pssh_b64,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class VideoStreaming:
    """HLS/DASH adaptive-bitrate streaming bookkeeping, in-memory."""

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._lock = threading.RLock()
        self._seed = _DEFAULT_SEED if seed is None else bytes(seed)
        self._last_seq = -1
        self._counter = 0
        self._assets: Dict[str, AssetRecord] = {}
        self._manifests: Dict[str, ManifestRecord] = {}
        self._segments: Dict[str, SegmentRecord] = {}
        self._drms: Dict[str, DRMRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _advance(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _reject(self, kind: str, seq: Any, record_id: str) -> VideoStreamingError:
        err = ValidationError(f"rejected: {kind}")
        try:
            self._audit.append(video_streaming_audit_event("rejected", seq, record_id))
        except VideoStreamingError:
            pass
        return err

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def _require_asset(self, asset_id: str) -> AssetRecord:
        asset = self._assets.get(asset_id)
        if asset is None:
            raise UnknownAssetError(f"unknown asset: {asset_id!r}")
        return asset

    def _derive_key_id(self, asset_id: str, system: str) -> str:
        material = hashlib.sha256(
            b"|".join([b"video-streaming.key", self._seed, asset_id.encode(), system.encode()])
        ).hexdigest()
        return material[:32]

    def _segment_ms(self, fmt: str) -> int:
        return HLS_SEGMENT_MS if fmt == "hls" else DASH_SEGMENT_MS

    def _segment_count(self, asset: AssetRecord, fmt: str) -> int:
        seg_ms = self._segment_ms(fmt)
        return (asset.duration_ms + seg_ms - 1) // seg_ms

    def _segment_duration_ms(self, asset: AssetRecord, fmt: str, index: int) -> int:
        seg_ms = self._segment_ms(fmt)
        start = index * seg_ms
        return min(seg_ms, asset.duration_ms - start)

    def _segment_uri(self, asset_id: str, track_index: int, segment_index: int) -> str:
        return f"{asset_id}/t{track_index}/seg-{segment_index}.m4s"

    def _segment_bytes(
        self, asset: AssetRecord, track_index: int, segment_index: int, fmt: str
    ) -> Tuple[int, int]:
        """Deterministic byte range derived from the pinned bitrate."""
        bitrate = asset.tracks[track_index].bitrate_kbps
        seg_ms = self._segment_ms(fmt)
        start = 0
        for i in range(segment_index):
            start += bitrate * self._segment_duration_ms(asset, fmt, i) // 8
        size = bitrate * self._segment_duration_ms(asset, fmt, segment_index) // 8
        return start, start + size

    # -- asset ----------------------------------------------------------

    def register_asset(
        self, asset_id: str, duration_ms: int, seq: int, tracks: Sequence[Mapping[str, Any]] = ()
    ) -> AssetRecord:
        """Book a source asset with its rendition ladder (host-reported)."""
        with self._lock:
            seq = self._advance(seq)
            asset_id = _check_asset_id(asset_id)
            if asset_id in self._assets:
                raise DuplicateAssetError(f"asset already registered: {asset_id!r}")
            duration_ms = _check_duration_ms(duration_ms)
            if not tracks:
                raise BadTrackError("at least one track is required")
            parsed = tuple(_check_track(t) for t in tracks)
            digest = _pin(
                ["asset", asset_id, duration_ms, [t.as_dict() for t in parsed]]
            )
            record = AssetRecord(
                asset_id=asset_id,
                duration_ms=duration_ms,
                tracks=parsed,
                digest=digest,
            )
            self._assets[asset_id] = record
            self._audit.append(
                video_streaming_audit_event("asset-registered", seq, asset_id)
            )
            return record

    # -- manifest -------------------------------------------------------

    def _hls_key_line(self, drm: DRMRecord, media_seq: int) -> str:
        method, keyformat = _HLS_KEY_METHODS[drm.system]
        iv = f"{media_seq:032x}"
        return (
            f'#EXT-X-KEY:METHOD={method},URI="{drm.license_url}",'
            f'KEYFORMAT="{keyformat}",IV=0x{iv}'
        )

    def _render_hls_master(self, asset: AssetRecord, drm: Optional[DRMRecord]) -> str:
        lines = ["#EXTM3U", "#EXT-X-VERSION:6", "#EXT-X-INDEPENDENT-SEGMENTS"]
        audio_tracks = [t for t in asset.tracks if t.kind == "audio"]
        video_tracks = [t for t in asset.tracks if t.kind == "video"]
        if audio_tracks:
            first = audio_tracks[0]
            lines.append(
                '#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",'
                f'NAME="{first.language}",LANGUAGE="{first.language}",'
                'DEFAULT=YES,AUTOSELECT=YES,'
                f'CHANNELS="{first.channels}",URI="audio-0.m3u8"'
            )
        for idx, track in enumerate(asset.tracks):
            if track.kind != "video":
                continue
            bandwidth = track.bitrate_kbps * 1000
            codecs = track.hls_codec_attr()
            if audio_tracks:
                codecs += "," + audio_tracks[0].hls_codec_attr()
            audio_attr = ',AUDIO="audio"' if audio_tracks else ""
            lines.append(
                f"#EXT-X-STREAM-INF:BANDWIDTH={bandwidth},"
                f"RESOLUTION={track.width}x{track.height},"
                f'CODECS="{codecs}"{audio_attr},'
                f"FRAME-RATE={track.fps:.3f}"
            )
            if drm is not None:
                lines.append(f"#EXT-X-SESSION-DATA:DATA-ID=\"drm\",VALUE=\"{drm.system}\"")
            lines.append(f"video-{idx}.m3u8")
        return "\n".join(lines) + "\n"

    def _render_hls_media(
        self, asset: AssetRecord, track_index: int, drm: Optional[DRMRecord]
    ) -> str:
        track = asset.tracks[track_index]
        count = self._segment_count(asset, "hls")
        target = (HLS_SEGMENT_MS + 999) // 1000
        lines = [
            "#EXTM3U",
            "#EXT-X-VERSION:6",
            f"#EXT-X-TARGETDURATION:{target}",
            "#EXT-X-MEDIA-SEQUENCE:0",
            "#EXT-X-PLAYLIST-TYPE:VOD",
        ]
        if drm is not None:
            lines.append(self._hls_key_line(drm, 0))
        for i in range(count):
            dur_ms = self._segment_duration_ms(asset, "hls", i)
            lines.append(f"#EXTINF:{dur_ms / 1000:.3f},")
            lines.append(self._segment_uri(asset.asset_id, track_index, i))
        lines.append("#EXT-X-ENDLIST")
        return "\n".join(lines) + "\n"

    def _render_dash_mpd(self, asset: AssetRecord, drm: Optional[DRMRecord]) -> str:
        total_s = asset.duration_ms / 1000
        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" '
            f'mediaPresentationDuration="PT{total_s:.3f}S" '
            'minBufferTime="PT2.000S" '
            'profiles="urn:mpeg:dash:profile:isoff-live:2011">',
            f'  <Period duration="PT{total_s:.3f}S">',
        ]
        for idx, track in enumerate(asset.tracks):
            if track.kind == "video":
                mime = "video/mp4"
                attrs = (
                    f'mimeType="{mime}" codecs="{track.hls_codec_attr()}" '
                    f'width="{track.width}" height="{track.height}" '
                    f'frameRate="{track.fps:.3f}"'
                )
            else:
                mime = "audio/mp4"
                attrs = (
                    f'mimeType="{mime}" codecs="{track.hls_codec_attr()}" '
                    f'audioSamplingRate="48000"'
                )
            bandwidth = track.bitrate_kbps * 1000
            lines.append(f"    <AdaptationSet {attrs}>")
            if drm is not None:
                scheme = _DRM_SCHEME_URIS[drm.system]
                lines.append(
                    f'      <ContentProtection schemeIdUri="{scheme}">'
                )
                lines.append(f"        <cenc:pssh>{drm.pssh_b64}</cenc:pssh>")
                lines.append("      </ContentProtection>")
            lines.append(
                f'      <Representation id="t{idx}" bandwidth="{bandwidth}">'
            )
            lines.append(
                f'        <SegmentTemplate timescale="1000" duration="{DASH_SEGMENT_MS}" '
                f'media="{asset.asset_id}/t{idx}/seg-$Number$.m4s" startNumber="0"/>'
            )
            lines.append("      </Representation>")
            lines.append("    </AdaptationSet>")
        lines.append("  </Period>")
        lines.append("</MPD>")
        return "\n".join(lines) + "\n"

    def _resolve_drm(self, asset_id: str, drm_id: Optional[str]) -> Optional[DRMRecord]:
        if drm_id is None:
            return None
        drm = self._drms.get(drm_id)
        if drm is None:
            raise UnknownDRMError(f"unknown drm binding: {drm_id!r}")
        if drm.asset_id != asset_id:
            raise ValidationError("drm binding belongs to a different asset")
        return drm

    def manifest(
        self,
        asset_id: str,
        seq: int,
        format: str = "hls",
        drm_id: Optional[str] = None,
    ) -> ManifestRecord:
        """Render the master manifest (HLS multivariant or DASH MPD)."""
        with self._lock:
            seq = self._advance(seq)
            fmt = _check_format(format)
            asset = self._require_asset(_check_asset_id(asset_id))
            drm = self._resolve_drm(asset.asset_id, drm_id)
            if fmt == "hls":
                text = self._render_hls_master(asset, drm)
            else:
                text = self._render_dash_mpd(asset, drm)
            digest = _pin(
                ["manifest", asset.asset_id, fmt, "master", None, text, drm_id]
            )
            record = ManifestRecord(
                manifest_id=self._next_id("mft"),
                asset_id=asset.asset_id,
                format=fmt,
                kind="master",
                track_index=None,
                text=text,
                drm_id=drm_id,
                digest=digest,
            )
            self._manifests[record.manifest_id] = record
            self._audit.append(
                video_streaming_audit_event("manifest-built", seq, record.manifest_id)
            )
            return record

    def media_playlist(
        self,
        asset_id: str,
        track_index: int,
        seq: int,
        drm_id: Optional[str] = None,
    ) -> ManifestRecord:
        """Render an HLS per-track media playlist (VOD)."""
        with self._lock:
            seq = self._advance(seq)
            asset = self._require_asset(_check_asset_id(asset_id))
            if (
                isinstance(track_index, bool)
                or not isinstance(track_index, int)
                or not (0 <= track_index < len(asset.tracks))
            ):
                raise OutOfRangeError("track_index out of range")
            drm = self._resolve_drm(asset.asset_id, drm_id)
            text = self._render_hls_media(asset, track_index, drm)
            digest = _pin(
                ["manifest", asset.asset_id, "hls", "media", track_index, text, drm_id]
            )
            record = ManifestRecord(
                manifest_id=self._next_id("mft"),
                asset_id=asset.asset_id,
                format="hls",
                kind="media",
                track_index=track_index,
                text=text,
                drm_id=drm_id,
                digest=digest,
            )
            self._manifests[record.manifest_id] = record
            self._audit.append(
                video_streaming_audit_event("manifest-built", seq, record.manifest_id)
            )
            return record

    # -- segment --------------------------------------------------------

    def segment(
        self, asset_id: str, track_index: int, segment_index: int, seq: int
    ) -> SegmentRecord:
        """Book one planned segment in the (track, index) lattice."""
        with self._lock:
            seq = self._advance(seq)
            asset = self._require_asset(_check_asset_id(asset_id))
            if (
                isinstance(track_index, bool)
                or not isinstance(track_index, int)
                or not (0 <= track_index < len(asset.tracks))
            ):
                raise OutOfRangeError("track_index out of range")
            if isinstance(segment_index, bool) or not isinstance(segment_index, int):
                raise OutOfRangeError("segment_index must be an int, not bool")
            count = self._segment_count(asset, "hls")
            if not (0 <= segment_index < count):
                raise OutOfRangeError(
                    f"segment_index out of range [0, {count}) for "
                    f"{asset.duration_ms}ms at {HLS_SEGMENT_MS}ms segments"
                )
            uri = self._segment_uri(asset.asset_id, track_index, segment_index)
            duration_ms = self._segment_duration_ms(asset, "hls", segment_index)
            start_byte, end_byte = self._segment_bytes(
                asset, track_index, segment_index, "hls"
            )
            digest = _pin(
                [
                    "segment",
                    asset.asset_id,
                    track_index,
                    segment_index,
                    uri,
                    duration_ms,
                    start_byte,
                    end_byte,
                ]
            )
            record = SegmentRecord(
                segment_id=self._next_id("seg"),
                asset_id=asset.asset_id,
                track_index=track_index,
                segment_index=segment_index,
                uri=uri,
                duration_ms=duration_ms,
                start_byte=start_byte,
                end_byte=end_byte,
                digest=digest,
            )
            self._segments[record.segment_id] = record
            self._audit.append(
                video_streaming_audit_event("segment-emitted", seq, record.segment_id)
            )
            return record

    # -- drm ------------------------------------------------------------

    def drm(
        self,
        asset_id: str,
        seq: int,
        system: str = "widevine",
        license_url: str = "",
    ) -> DRMRecord:
        """Book a DRM key binding for an asset (simulated key_id + PSSH)."""
        with self._lock:
            seq = self._advance(seq)
            asset = self._require_asset(_check_asset_id(asset_id))
            system = _check_drm_system(system)
            if not isinstance(license_url, str):
                raise ValidationError("license_url must be a str")
            for existing in self._drms.values():
                if existing.asset_id == asset.asset_id and existing.system == system:
                    raise DuplicateDRMError(
                        f"drm already bound for {asset.asset_id}/{system}"
                    )
            key_id = self._derive_key_id(asset.asset_id, system)
            pssh_b64 = base64.b64encode(f"pssh:{system}:{key_id}".encode()).decode()
            digest = _pin(
                ["drm", asset.asset_id, system, key_id, license_url, pssh_b64]
            )
            record = DRMRecord(
                drm_id=self._next_id("drm"),
                asset_id=asset.asset_id,
                system=system,
                key_id=key_id,
                license_url=license_url,
                pssh_b64=pssh_b64,
                digest=digest,
            )
            self._drms[record.drm_id] = record
            self._audit.append(
                video_streaming_audit_event("drm-bound", seq, record.drm_id)
            )
            return record

    # -- views ----------------------------------------------------------

    def asset(self, asset_id: str) -> AssetRecord:
        with self._lock:
            return self._require_asset(_check_asset_id(asset_id))

    def manifest_record(self, manifest_id: str) -> ManifestRecord:
        with self._lock:
            record = self._manifests.get(manifest_id)
            if record is None:
                raise UnknownManifestError(f"unknown manifest: {manifest_id!r}")
            return record

    def segment_record(self, segment_id: str) -> SegmentRecord:
        with self._lock:
            record = self._segments.get(segment_id)
            if record is None:
                raise UnknownSegmentError(f"unknown segment: {segment_id!r}")
            return record

    def drm_record(self, drm_id: str) -> DRMRecord:
        with self._lock:
            record = self._drms.get(drm_id)
            if record is None:
                raise UnknownDRMError(f"unknown drm binding: {drm_id!r}")
            return record

    def segment_count(self, asset_id: str) -> int:
        """Number of HLS segments per track for the asset."""
        with self._lock:
            asset = self._require_asset(_check_asset_id(asset_id))
            return self._segment_count(asset, "hls")

    def asset_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._assets)

    def manifest_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._manifests)

    def segment_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._segments)

    def drm_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._drms)

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "assets": [a.as_dict() for a in self._assets.values()],
                "manifests": [m.as_dict() for m in self._manifests.values()],
                "segments": [s.as_dict() for s in self._segments.values()],
                "drms": [d.as_dict() for d in self._drms.values()],
            }


def video_streaming_audit_event(
    kind: str, seq: int, record_id: str
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids/digests only)."""
    if kind not in (
        "asset-registered",
        "manifest-built",
        "segment-emitted",
        "drm-bound",
        "rejected",
    ):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    if not isinstance(record_id, str):
        raise ValidationError("record_id must be a str")
    return {
        "kind": kind,
        "seq": seq,
        "record_id": record_id,
        "module": "video-streaming",
        "version": VIDEO_STREAMING_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    vs = VideoStreaming()
    asset = vs.register_asset(
        "movie-1",
        60_000,
        1,
        tracks=[
            {
                "kind": "video",
                "codec": "h264",
                "bitrate_kbps": 8000,
                "width": 1920,
                "height": 1080,
                "fps": 30.0,
            },
            {
                "kind": "audio",
                "codec": "aac",
                "bitrate_kbps": 128,
                "channels": 2,
                "language": "en",
            },
        ],
    )
    assert asset.verify()
    assert vs.segment_count("movie-1") == 10
    mft = vs.manifest("movie-1", 2)
    assert mft.verify()
    assert "#EXT-X-STREAM-INF" in mft.text and "RESOLUTION=1920x1080" in mft.text
    media = vs.media_playlist("movie-1", 0, 3)
    assert media.verify() and "#EXT-X-ENDLIST" in media.text
    seg = vs.segment("movie-1", 0, 0, 4)
    assert seg.verify() and seg.duration_ms == 6000
    drm = vs.drm("movie-1", 5, system="widevine", license_url="https://lic.example/wv")
    assert drm.verify() and len(drm.key_id) == 32
    protected = vs.manifest("movie-1", 6, drm_id=drm.drm_id)
    assert "#EXT-X-SESSION-DATA" in protected.text
    protected_media = vs.media_playlist("movie-1", 0, 7, drm_id=drm.drm_id)
    assert "#EXT-X-KEY" in protected_media.text
    print("video-streaming OK: register, manifest, media, segment, drm, pins")
