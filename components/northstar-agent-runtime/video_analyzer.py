"""Video analyzer interface (scene detection + motion estimation, simulated).

Research motivation: every agent that touches video -- moderation triage,
meeting summarization, surveillance review, sports highlights -- needs the
same three primitives: *where the cuts are* (shot boundary detection),
*how much is moving* (motion estimation), and *which frames matter*
(keyframe selection). The industry shape is the same everywhere (FFmpeg
``select='gt(scene,0.4)'``, PySceneDetect's content detector, OpenCV
frame differencing): compare consecutive frames, threshold the
difference, emit boundaries.

This module is the *bookkeeping* half of that shape:

- ``VideoAnalyzer`` -- ``register_video()`` pins a video's shape
  (frame count, fps, feature length); ``report_frame()`` records one
  frame's host-reported feature vector (a small integer luma signature,
  not pixels); ``scenes()`` walks adjacent frames and cuts where the
  L1 distance crosses ``cut_threshold_bp``; ``motion()`` reports a
  per-frame motion score against a sliding window; ``keyframes()``
  selects the union of the first frame, every scene start, and every
  ``interval``-th frame.
- ``video_analyzer_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``video-registered`` / ``frame-reported`` /
  ``scenes-detected`` / ``motion-estimated`` / ``keyframes-selected``
  / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``video_id`` is a non-empty ``str``; ``frame_count`` and
  ``feature_len`` are ints (not bool) >= 1; ``fps`` is an int (not
  bool) >= 1; ``frame_index`` is an int (not bool) in
  ``[0, frame_count)``; caller seqs are ints (not bool) and must be
  strictly increasing per analyzer instance. A failed mutation still
  consumes its seq (fail-closed ledger position).
- Frame features are exactly ``feature_len`` ints (not bool) in
  ``[0, 255]`` -- the tiny luma signature the host asserts for that
  frame. Duplicate ``(video_id, frame_index)`` reports are refused.
- ``scenes()`` / ``motion()`` / ``keyframes()`` refuse until every
  frame of the video has been reported (``MissingFramesError``) -- a
  cut computed from a partial ledger is a lie of omission.
- ``cut_threshold_bp`` is an int (not bool) in ``[1, 10000]``
  (basis points of the maximum L1 distance); ``window`` and
  ``interval`` are ints (not bool) >= 1.
- Distances are exact integer math: L1 distance scaled to basis
  points with round-half-up, so pins never see a float.

Honest scope:

- This module books *reported* video analysis. The "frames" are
  host-asserted feature vectors, not decoded pixels; a "cut" means
  "the reported signatures jumped", never "a real shot boundary
  exists" (GIGO boundary). It cannot decode video, cannot prove a
  video exists, and cannot see frames the host did not report.
- A ``motion_bp`` of 0 means "the reported signature did not change
  against the window", not "nothing moved in the real world".
- In-memory only: pair with the durable audit writer if analysis
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
VIDEO_ANALYZER_VERSION = "video-analyzer.v1"

#: Schema pin carried by records and audit events.
VIDEO_ANALYZER_SCHEMA = "northstar.video-analyzer.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Default cut threshold: 35% of the maximum L1 feature distance.
DEFAULT_CUT_THRESHOLD_BP = 3500

#: Default keyframe interval (every Nth frame).
DEFAULT_KEYFRAME_INTERVAL = 30

#: Keyframe reason pins.
REASON_FIRST_FRAME = "first-frame"
REASON_SCENE_START = "scene-start"
REASON_INTERVAL = "interval"


class VideoAnalyzerError(ValueError):
    """Base fail-closed video-analyzer error."""


class UnknownVideoError(VideoAnalyzerError):
    """No video registered under this id."""


class DuplicateVideoError(VideoAnalyzerError):
    """A video is already registered under this id."""


class DuplicateFrameError(VideoAnalyzerError):
    """This frame index was already reported for the video."""


class BadFeatureError(VideoAnalyzerError):
    """Frame feature vector has the wrong shape or bad values."""


class BadVideoSpecError(VideoAnalyzerError):
    """Registration arguments are malformed."""


class MissingFramesError(VideoAnalyzerError):
    """Analysis refused: not every frame was reported yet."""


class BadThresholdError(VideoAnalyzerError):
    """Cut threshold / window / interval out of range."""


class SeqOrderError(VideoAnalyzerError):
    """Caller seq is not a strictly increasing int."""


def _pin(body: Any) -> str:
    return "sha256:" + jcs_sha256_hex(body)


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadVideoSpecError(f"{name} must be a non-empty str")
    return value


def _check_pos_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BadVideoSpecError(f"{name} must be an int >= 1")
    return value


def _l1_distance_bp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """L1 distance between two feature vectors, in basis points [0, 10000].

    Exact integer math with round-half-up; never touches a float.
    """
    total = sum(abs(x - y) for x, y in zip(a, b))
    denom = len(a) * 255
    return (total * 10000 + denom // 2) // denom


@dataclass(frozen=True)
class VideoRecord:
    """Pinned registration of one video's shape."""

    video_id: str
    frame_count: int
    fps: int
    feature_len: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "frame_count": self.frame_count,
            "fps": self.fps,
            "feature_len": self.feature_len,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class FrameRecord:
    """One host-reported frame feature vector."""

    video_id: str
    frame_index: int
    feature: Tuple[int, ...]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "frame_index": self.frame_index,
            "feature": list(self.feature),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Scene:
    """One detected shot: inclusive [start_frame, end_frame]."""

    start_frame: int
    end_frame: int

    def as_dict(self) -> Dict[str, Any]:
        return {"start_frame": self.start_frame, "end_frame": self.end_frame}


@dataclass(frozen=True)
class SceneReport:
    """Shot boundaries for a video."""

    video_id: str
    cut_threshold_bp: int
    scenes: Tuple[Scene, ...]
    cut_frames: Tuple[int, ...]
    scene_count: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "cut_threshold_bp": self.cut_threshold_bp,
            "scenes": [s.as_dict() for s in self.scenes],
            "cut_frames": list(self.cut_frames),
            "scene_count": self.scene_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class MotionSample:
    """Per-frame motion score in basis points [0, 10000]."""

    frame_index: int
    motion_bp: int

    def as_dict(self) -> Dict[str, Any]:
        return {"frame_index": self.frame_index, "motion_bp": self.motion_bp}


@dataclass(frozen=True)
class MotionReport:
    """Motion estimation across a video."""

    video_id: str
    window: int
    samples: Tuple[MotionSample, ...]
    avg_motion_bp: int
    max_motion_frame: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "window": self.window,
            "samples": [s.as_dict() for s in self.samples],
            "avg_motion_bp": self.avg_motion_bp,
            "max_motion_frame": self.max_motion_frame,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Keyframe:
    """One selected keyframe and why it was selected."""

    frame_index: int
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {"frame_index": self.frame_index, "reason": self.reason}


@dataclass(frozen=True)
class KeyframeReport:
    """Keyframe selection for a video."""

    video_id: str
    interval: int
    keyframes: Tuple[Keyframe, ...]
    count: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "video_id": self.video_id,
            "interval": self.interval,
            "keyframes": [k.as_dict() for k in self.keyframes],
            "count": self.count,
            "digest": self.digest,
        }


class VideoAnalyzer:
    """Scene detection + motion estimation over reported frame features.

    Single-host, RLock-guarded, deterministic. Caller-supplied strictly
    increasing int seqs are the only clock; no wall-clock, no RNG.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._videos: Dict[str, VideoRecord] = {}
        self._specs: Dict[str, Tuple[int, int]] = {}  # video_id -> (frame_count, feature_len)
        self._frames: Dict[Tuple[str, int], FrameRecord] = {}

    # -- internal ----------------------------------------------------

    def _claim(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq  # failed mutations still consume their seq (fail-closed)

    def _get(self, video_id: str) -> VideoRecord:
        try:
            return self._videos[video_id]
        except KeyError:
            raise UnknownVideoError(f"unknown video: {video_id!r}") from None

    def _all_features(self, video: VideoRecord) -> Tuple[Tuple[int, ...], ...]:
        missing = [
            i
            for i in range(video.frame_count)
            if (video.video_id, i) not in self._frames
        ]
        if missing:
            raise MissingFramesError(
                f"{len(missing)} frame(s) not reported yet (first: {missing[0]})"
            )
        return tuple(
            self._frames[(video.video_id, i)].feature
            for i in range(video.frame_count)
        )

    # -- registration -------------------------------------------------

    def register_video(
        self,
        video_id: str,
        frame_count: int,
        fps: int,
        seq: int,
        feature_len: int = 16,
    ) -> VideoRecord:
        """Pin a video's shape before any frame is reported."""
        with self._lock:
            self._claim(seq)
            _check_id(video_id, "video_id")
            _check_pos_int(frame_count, "frame_count")
            _check_pos_int(fps, "fps")
            _check_pos_int(feature_len, "feature_len")
            if video_id in self._videos:
                raise DuplicateVideoError(f"video already registered: {video_id!r}")
            body = {
                "video_id": video_id,
                "frame_count": frame_count,
                "fps": fps,
                "feature_len": feature_len,
            }
            record = VideoRecord(
                video_id=video_id,
                frame_count=frame_count,
                fps=fps,
                feature_len=feature_len,
                digest=_pin(body),
            )
            self._videos[video_id] = record
            self._specs[video_id] = (frame_count, feature_len)
            return record

    def report_frame(
        self,
        video_id: str,
        frame_index: int,
        feature: Any,
        seq: int,
    ) -> FrameRecord:
        """Record one frame's host-asserted feature vector."""
        with self._lock:
            self._claim(seq)
            video = self._get(video_id)
            if isinstance(frame_index, bool) or not isinstance(frame_index, int):
                raise BadFeatureError("frame_index must be an int")
            if not 0 <= frame_index < video.frame_count:
                raise BadFeatureError(
                    f"frame_index {frame_index} out of range [0, {video.frame_count})"
                )
            key = (video_id, frame_index)
            if key in self._frames:
                raise DuplicateFrameError(
                    f"frame {frame_index} already reported for {video_id!r}"
                )
            if not isinstance(feature, (tuple, list)) or len(feature) != video.feature_len:
                raise BadFeatureError(
                    f"feature must be a sequence of {video.feature_len} ints"
                )
            vals = tuple(feature)
            for v in vals:
                if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 255:
                    raise BadFeatureError(
                        "feature values must be ints in [0, 255]"
                    )
            record = FrameRecord(
                video_id=video_id,
                frame_index=frame_index,
                feature=vals,
                digest=_pin(
                    {"video_id": video_id, "frame_index": frame_index,
                     "feature": list(vals)}
                ),
            )
            self._frames[key] = record
            return record

    # -- analysis -----------------------------------------------------

    def scenes(
        self,
        video_id: str,
        seq: int,
        cut_threshold_bp: int = DEFAULT_CUT_THRESHOLD_BP,
    ) -> SceneReport:
        """Detect shot boundaries: cut where adjacent L1 distance >= threshold."""
        with self._lock:
            self._claim(seq)
            video = self._get(video_id)
            if (
                isinstance(cut_threshold_bp, bool)
                or not isinstance(cut_threshold_bp, int)
                or not 1 <= cut_threshold_bp <= 10000
            ):
                raise BadThresholdError("cut_threshold_bp must be an int in [1, 10000]")
            feats = self._all_features(video)
            cuts: list[int] = []
            for i in range(1, len(feats)):
                if _l1_distance_bp(feats[i - 1], feats[i]) >= cut_threshold_bp:
                    cuts.append(i)
            scenes: list[Scene] = []
            start = 0
            for cut in cuts:
                scenes.append(Scene(start_frame=start, end_frame=cut - 1))
                start = cut
            scenes.append(Scene(start_frame=start, end_frame=len(feats) - 1))
            body = {
                "video_id": video_id,
                "cut_threshold_bp": cut_threshold_bp,
                "scenes": [s.as_dict() for s in scenes],
                "cut_frames": cuts,
            }
            return SceneReport(
                video_id=video_id,
                cut_threshold_bp=cut_threshold_bp,
                scenes=tuple(scenes),
                cut_frames=tuple(cuts),
                scene_count=len(scenes),
                digest=_pin(body),
            )

    def motion(self, video_id: str, seq: int, window: int = 1) -> MotionReport:
        """Per-frame motion score: L1 distance to the frame `window` back.

        Frames with no baseline (index < window) score 0 -- documented,
        not guessed.
        """
        with self._lock:
            self._claim(seq)
            video = self._get(video_id)
            if isinstance(window, bool) or not isinstance(window, int) or window < 1:
                raise BadThresholdError("window must be an int >= 1")
            feats = self._all_features(video)
            samples: list[MotionSample] = []
            total = 0
            max_bp = -1
            max_frame = 0
            for i, feat in enumerate(feats):
                if i < window:
                    score = 0
                else:
                    score = _l1_distance_bp(feats[i - window], feat)
                samples.append(MotionSample(frame_index=i, motion_bp=score))
                total += score
                if score > max_bp:
                    max_bp = score
                    max_frame = i
            n = len(samples)
            avg = (total + n // 2) // n  # round-half-up, exact ints
            report = MotionReport(
                video_id=video_id,
                window=window,
                samples=tuple(samples),
                avg_motion_bp=avg,
                max_motion_frame=max_frame,
                digest=_pin(
                    {
                        "video_id": video_id,
                        "window": window,
                        "samples": [s.as_dict() for s in samples],
                        "avg_motion_bp": avg,
                        "max_motion_frame": max_frame,
                    }
                ),
            )
            return report

    def keyframes(
        self,
        video_id: str,
        seq: int,
        interval: int = DEFAULT_KEYFRAME_INTERVAL,
        cut_threshold_bp: int = DEFAULT_CUT_THRESHOLD_BP,
    ) -> KeyframeReport:
        """Select keyframes: frame 0, every scene start, every `interval`-th frame.

        Scene starts are re-derived here with `cut_threshold_bp` so the
        definition of a scene matches the caller's chosen threshold;
        this re-derivation consumes no extra seq (same ledger position).

        Reason precedence on overlap: first-frame > scene-start > interval.
        """
        with self._lock:
            self._claim(seq)
            video = self._get(video_id)
            if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
                raise BadThresholdError("interval must be an int >= 1")
            if (
                isinstance(cut_threshold_bp, bool)
                or not isinstance(cut_threshold_bp, int)
                or not 1 <= cut_threshold_bp <= 10000
            ):
                raise BadThresholdError("cut_threshold_bp must be an int in [1, 10000]")
            feats = self._all_features(video)
            cut_set = set()
            for i in range(1, len(feats)):
                if _l1_distance_bp(feats[i - 1], feats[i]) >= cut_threshold_bp:
                    cut_set.add(i)
            reasons: Dict[int, str] = {0: REASON_FIRST_FRAME}
            for cut in sorted(cut_set):
                reasons.setdefault(cut, REASON_SCENE_START)
            i = 0
            while i < video.frame_count:
                reasons.setdefault(i, REASON_INTERVAL)
                i += interval
            ordered = [Keyframe(frame_index=f, reason=reasons[f]) for f in sorted(reasons)]
            return KeyframeReport(
                video_id=video_id,
                interval=interval,
                keyframes=tuple(ordered),
                count=len(ordered),
                digest=_pin(
                    {
                        "video_id": video_id,
                        "interval": interval,
                        "keyframes": [k.as_dict() for k in ordered],
                    }
                ),
            )

    # -- views --------------------------------------------------------

    def video(self, video_id: str) -> VideoRecord:
        """Read back a video's pinned registration."""
        with self._lock:
            return self._get(video_id)

    def video_ids(self) -> Tuple[str, ...]:
        """All registered video ids, sorted."""
        with self._lock:
            return tuple(sorted(self._videos))

    def frame(self, video_id: str, frame_index: int) -> FrameRecord:
        """Read back one reported frame."""
        with self._lock:
            self._get(video_id)
            try:
                return self._frames[(video_id, frame_index)]
            except KeyError:
                raise UnknownVideoError(
                    f"frame {frame_index} not reported for {video_id!r}"
                ) from None

    def frames_reported(self, video_id: str) -> int:
        """How many frames have been reported for this video."""
        with self._lock:
            self._get(video_id)
            return sum(1 for (vid, _i) in self._frames if vid == video_id)


#: Fixed audit kinds for this module.
_VIDEO_ANALYZER_AUDIT_KINDS = (
    "video-registered",
    "frame-reported",
    "scenes-detected",
    "motion-estimated",
    "keyframes-selected",
    "rejected",
)


def video_analyzer_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module.

    Carries ids, seqs, and digest pins only -- never frame features.
    """
    if kind not in _VIDEO_ANALYZER_AUDIT_KINDS:
        raise VideoAnalyzerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    body = {
        "schema": AUDIT_SCHEMA,
        "module": VIDEO_ANALYZER_SCHEMA,
        "version": VIDEO_ANALYZER_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail) if detail else {},
    }
    body["pin"] = _pin(body)
    return body


def main() -> None:
    """Self-check: two shots, one cut, interval keyframes."""
    va = VideoAnalyzer()
    va.register_video("demo", frame_count=6, fps=30, seq=1, feature_len=4)
    dark = (10, 10, 10, 10)
    bright = (200, 200, 200, 200)
    for i, feat in enumerate([dark, dark, dark, bright, bright, bright]):
        va.report_frame("demo", i, feat, seq=2 + i)
    scenes = va.scenes("demo", seq=8)
    assert scenes.cut_frames == (3,), scenes.cut_frames
    assert scenes.scene_count == 2
    motion = va.motion("demo", seq=9)
    assert motion.max_motion_frame == 3, motion.max_motion_frame
    keys = va.keyframes("demo", seq=10, interval=2)
    assert [k.frame_index for k in keys.keyframes] == [0, 2, 3, 4]
    print("video-analyzer OK: register, scenes, motion, keyframes")


if __name__ == "__main__":
    main()
