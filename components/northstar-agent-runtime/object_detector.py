"""Object detection interface (YOLO-shaped bookkeeping).

Research motivation: an agent runtime that consumes cameras or image
feeds needs a stable "what is in this frame" contract before it can
build anything else -- safety gates, surveillance summaries, robot
perception, UI automation. Industry practice (YOLOv8, DETR,
EfficientDet, torchvision Mask R-CNN) converges on the same three
bookkeeping primitives this module pins:

- *detect*: a frame -> list of (box, class, confidence) predictions,
  with confidence-threshold filtering and class-wise non-maximum
  suppression (NMS) by IoU;
- *track*: detections across successive frames -> persistent track
  ids via greedy IoU association;
- *count*: a detection report -> per-class counts.

This module is the *bookkeeping* half of that shape, following the
runtime's house discipline:

- ``ObjectDetector`` -- ``detect()`` filters, NMSes, and pins a
  host-reported candidate list; ``track()`` associates the detections
  of one frame with live tracks; ``count()`` tallies per-class
  counts. ``tracks()`` / ``image_ids()`` are read views.
- ``object_detector_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``detected`` / ``tracked`` / ``counted`` / ``rejected``);
  caller-supplied seqs only.

Box geometry: YOLO center format ``(x_center, y_center, width,
height)``, all in normalized [0, 1] frame coordinates. IoU is the
usual symmetric intersection-over-union over the decoded corner
boxes; NMS is greedy, per-class, descending confidence, ties broken
by ascending detection id (deterministic).

Fail-closed edges (fail loudly, never guess):

- ``class_name`` must be a member of the pinned ``CLASSES`` set
  (COCO-80-style vocabulary); unknown classes raise
  ``UnknownClassError`` at input time.
- Box components are finite floats in [0, 1] (NaN/inf/bool/str
  refused); ``width``/``height`` must be > 0; boxes are clipped to
  the frame (degenerate zero-area boxes after clipping raise
  ``BadBoxError``).
- ``confidence`` is a finite float in [0, 1]; the ``min_confidence``
  threshold is applied fail-closed (a candidate exactly at the
  threshold is kept).
- ``iou_threshold`` in (0, 1]; ``max_detections`` a positive int;
  ``track_max_age`` / ``track_min_iou`` bounds enforced at call time.
- ``seq`` is a caller-supplied strictly-increasing ``int`` (no
  wall clock anywhere); bool/negative/non-int seqs refused with
  ``SeqOrderError``.
- ``detect()`` never invents objects: an empty candidate list is an
  empty report, not an error; unknown track ids are refused, never
  silently dropped.

Honest scope:

- This module books *host-reported* candidate boxes. It does not run
  a neural network and cannot verify that a box really contains the
  claimed class; a lying host gets a lying report. NMS, tracking, and
  counting here are deterministic ledger operations over reported
  inputs, not perception.
- ``detect()`` pins what the detector *says*, never ground truth;
  confidence is host-asserted and means nothing outside the host's
  calibration.
- Everything is in-memory; pair with the durable audit writer if
  reports must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

import canonical_json  # noqa: F401,E402  (documents the canonical path)

OBJECT_DETECTOR_VERSION = "object-detector.v1"
OBJECT_DETECTOR_SCHEMA = "northstar.object-detector.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

# COCO-80-style class vocabulary, pinned as a closed set so a report
# never holds an unspellchecked class name.
CLASSES = (
    "person", "bicycle", "car", "motorcycle", "airplane", "bus",
    "train", "truck", "boat", "traffic_light", "fire_hydrant",
    "stop_sign", "parking_meter", "bench", "bird", "cat", "dog",
    "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe",
    "backpack", "umbrella", "handbag", "tie", "suitcase", "frisbee",
    "skis", "snowboard", "sports_ball", "kite", "baseball_bat",
    "baseball_glove", "skateboard", "surfboard", "tennis_racket",
    "bottle", "wine_glass", "cup", "fork", "knife", "spoon", "bowl",
    "banana", "apple", "sandwich", "orange", "broccoli", "carrot",
    "hot_dog", "pizza", "donut", "cake", "chair", "couch",
    "potted_plant", "bed", "dining_table", "toilet", "tv", "laptop",
    "mouse", "remote", "keyboard", "cell_phone", "microwave",
    "oven", "toaster", "sink", "refrigerator", "book", "clock",
    "vase", "scissors", "teddy_bear", "hair_drier", "toothbrush",
)

_ALLOWED_CLASSES = frozenset(CLASSES)

# Default knobs, pinned so replays are byte-identical.
DEFAULT_MIN_CONFIDENCE = 0.25
DEFAULT_IOU_THRESHOLD = 0.45
DEFAULT_MAX_DETECTIONS = 300
DEFAULT_TRACK_MAX_AGE = 3
DEFAULT_TRACK_MIN_IOU = 0.30
MAX_CANDIDATES = 10_000


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy).
# ---------------------------------------------------------------------------

class ObjectDetectorError(Exception):
    """Base fail-closed object-detector error."""


class UnknownClassError(ObjectDetectorError):
    """class_name is not in the pinned CLASSES vocabulary."""


class BadBoxError(ObjectDetectorError):
    """Box components are not finite [0,1] floats, or degenerate."""


class BadCandidateError(ObjectDetectorError):
    """Candidate mapping is malformed (confidence/keys)."""


class BadThresholdError(ObjectDetectorError):
    """min_confidence / iou_threshold / max_detections out of range."""


class TrackError(ObjectDetectorError):
    """Tracking inputs malformed (ages, IoU, empty ids)."""


class SeqOrderError(ObjectDetectorError):
    """seq is not a strictly-increasing non-bool int."""


class AuditKindError(ObjectDetectorError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Internal validators.
# ---------------------------------------------------------------------------

def _is_real_float(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if not isinstance(value, float):
        return False
    return value == value and value not in (float("inf"), float("-inf"))


def _check_unit(value: float, name: str) -> float:
    if not _is_real_float(value):
        raise BadBoxError(f"{name} must be a finite float, got {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadBoxError(f"{name} must be in [0, 1], got {value!r}")
    return value


def _clip01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _decode_corners(xc: float, yc: float, w: float, h: float) -> Tuple[float, float, float, float]:
    """Center-format -> clipped corner-format (x1, y1, x2, y2)."""
    x1 = _clip01(xc - w / 2.0)
    y1 = _clip01(yc - h / 2.0)
    x2 = _clip01(xc + w / 2.0)
    y2 = _clip01(yc + h / 2.0)
    return (x1, y1, x2, y2)


def _area(corners: Tuple[float, float, float, float]) -> float:
    x1, y1, x2, y2 = corners
    return max(0.0, x2 - x1) * max(0.0, y2 - y1)


def iou(a: Tuple[float, float, float, float],
        b: Tuple[float, float, float, float]) -> float:
    """Symmetric intersection-over-union of two corner boxes."""
    ax1, ay1, ax2, ay2 = a
    bx1, by1, bx2, by2 = b
    ix1 = max(ax1, bx1)
    iy1 = max(ay1, by1)
    ix2 = min(ax2, bx2)
    iy2 = min(ay2, by2)
    inter = max(0.0, ix2 - ix1) * max(0.0, iy2 - iy1)
    union = _area(a) + _area(b) - inter
    if union <= 0.0:
        return 0.0
    return inter / union


# ---------------------------------------------------------------------------
# Frozen records.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Detection:
    """One kept detection: class, YOLO center-format box, confidence."""
    detection_id: str
    class_name: str
    box: Tuple[float, float, float, float]  # (xc, yc, w, h)
    confidence: float
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "class_name": self.class_name,
            "box": list(self.box),
            "confidence": self.confidence,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DetectionReport:
    """Pinned result of one ``detect()`` call."""
    report_id: str
    image_id: str
    detections: Tuple[Detection, ...]
    kept: int
    suppressed: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "image_id": self.image_id,
            "detections": [d.as_dict() for d in self.detections],
            "kept": self.kept,
            "suppressed": self.suppressed,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Track:
    """One live track: id, class, last box, confidence, age."""
    track_id: str
    class_name: str
    box: Tuple[float, float, float, float]  # (xc, yc, w, h)
    confidence: float
    age: int
    frames_seen: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "track_id": self.track_id,
            "class_name": self.class_name,
            "box": list(self.box),
            "confidence": self.confidence,
            "age": self.age,
            "frames_seen": self.frames_seen,
        }


@dataclass(frozen=True)
class TrackReport:
    """Pinned result of one ``track()`` call."""
    report_id: str
    image_id: str
    tracks: Tuple[Track, ...]
    matched: int
    spawned: int
    expired: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "image_id": self.image_id,
            "tracks": [t.as_dict() for t in self.tracks],
            "matched": self.matched,
            "spawned": self.spawned,
            "expired": self.expired,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CountReport:
    """Per-class tallies derived from a ``DetectionReport``."""
    report_id: str
    source_report_id: str
    counts: Tuple[Tuple[str, int], ...]  # sorted by class name
    total: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "source_report_id": self.source_report_id,
            "counts": [list(pair) for pair in self.counts],
            "total": self.total,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The detector.
# ---------------------------------------------------------------------------

class ObjectDetector:
    """YOLO-shaped detection bookkeeping (simulated, no network).

    The host supplies candidate boxes (the model-output stub);
    ``detect()`` applies confidence filtering + class-wise greedy NMS
    and pins the kept list. ``track()`` associates detections across
    frames into persistent tracks by greedy IoU matching.
    ``count()`` tallies per-class counts from a detection report.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, DetectionReport] = {}
        self._report_count = 0
        self._tracks: Dict[str, Dict[str, Any]] = {}  # mutable ledger rows
        self._track_seq = 0
        self._audit_log: List[Dict[str, Any]] = []

    # -- seq discipline -------------------------------------------------

    def _next_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError(f"seq must be a positive int, got {seq!r}")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got {seq})")
        self._seq = seq

    def _digest(self, kind: str, body: Any) -> str:
        return "sha256:" + jcs_sha256_hex(
            {"v": OBJECT_DETECTOR_VERSION, "kind": kind, "body": body})

    def _audit(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        allowed = {"detected", "tracked", "counted", "rejected"}
        if kind not in allowed:
            raise AuditKindError(f"unknown audit kind {kind!r}")
        self._audit_log.append({
            "schema": AUDIT_SCHEMA,
            "module": OBJECT_DETECTOR_SCHEMA,
            "kind": kind,
            "seq": seq,
            "detail": dict(detail),
        })

    # -- input validation -----------------------------------------------

    def _check_candidate(self, cand: Mapping[str, Any], index: int) -> Dict[str, Any]:
        if not isinstance(cand, Mapping):
            raise BadCandidateError(f"candidate[{index}] must be a mapping")
        keys = {"class_name", "box", "confidence"}
        missing = keys - set(cand.keys())
        if missing:
            raise BadCandidateError(
                f"candidate[{index}] missing keys {sorted(missing)}")
        class_name = cand["class_name"]
        if not isinstance(class_name, str) or not class_name:
            raise BadCandidateError(
                f"candidate[{index}].class_name must be a non-empty str")
        if class_name not in _ALLOWED_CLASSES:
            raise UnknownClassError(
                f"candidate[{index}].class_name {class_name!r} not in vocabulary")
        box = cand["box"]
        if not isinstance(box, (list, tuple)) or len(box) != 4:
            raise BadBoxError(
                f"candidate[{index}].box must be a 4-tuple (xc, yc, w, h)")
        xc = _check_unit(box[0], f"candidate[{index}].box[0]")
        yc = _check_unit(box[1], f"candidate[{index}].box[1]")
        w = _check_unit(box[2], f"candidate[{index}].box[2]")
        h = _check_unit(box[3], f"candidate[{index}].box[3]")
        if w <= 0.0 or h <= 0.0:
            raise BadBoxError(
                f"candidate[{index}].box width/height must be > 0")
        corners = _decode_corners(xc, yc, w, h)
        if _area(corners) <= 0.0:
            raise BadBoxError(
                f"candidate[{index}].box clips to zero area")
        conf = cand["confidence"]
        if not _is_real_float(conf):
            raise BadCandidateError(
                f"candidate[{index}].confidence must be a finite float")
        if not 0.0 <= conf <= 1.0:
            raise BadCandidateError(
                f"candidate[{index}].confidence must be in [0, 1]")
        return {
            "class_name": class_name,
            "box": (xc, yc, w, h),
            "corners": corners,
            "confidence": conf,
        }

    def _check_thresholds(self, min_confidence: float, iou_threshold: float,
                          max_detections: int) -> None:
        if not _is_real_float(min_confidence) or not 0.0 <= min_confidence <= 1.0:
            raise BadThresholdError(
                f"min_confidence must be a finite float in [0, 1]")
        if not _is_real_float(iou_threshold) or not 0.0 < iou_threshold <= 1.0:
            raise BadThresholdError(
                f"iou_threshold must be a finite float in (0, 1]")
        if isinstance(max_detections, bool) or not isinstance(max_detections, int) \
                or max_detections <= 0:
            raise BadThresholdError(
                "max_detections must be a positive int")

    # -- public API ------------------------------------------------------

    def detect(self, image_id: str, candidates: List[Mapping[str, Any]],
               seq: int,
               min_confidence: float = DEFAULT_MIN_CONFIDENCE,
               iou_threshold: float = DEFAULT_IOU_THRESHOLD,
               max_detections: int = DEFAULT_MAX_DETECTIONS) -> DetectionReport:
        """Filter + NMS host-reported candidates, return a pinned report."""
        with self._lock:
            self._next_seq(seq)
            if not isinstance(image_id, str) or not image_id:
                raise BadCandidateError("image_id must be a non-empty str")
            self._check_thresholds(min_confidence, iou_threshold,
                                   max_detections)
            if not isinstance(candidates, list):
                raise BadCandidateError("candidates must be a list")
            if len(candidates) > MAX_CANDIDATES:
                raise BadCandidateError(
                    f"candidates capped at {MAX_CANDIDATES}")

            parsed = [self._check_candidate(c, i)
                      for i, c in enumerate(candidates)]

            # Confidence filter (fail-closed: exactly-at-threshold is kept).
            passed = [p for p in parsed if p["confidence"] >= min_confidence]
            pre_nms = len(passed)

            # Class-wise greedy NMS: descending confidence, ascending
            # input order as the deterministic tie-break.
            by_class: Dict[str, List[int]] = {}
            for idx, p in enumerate(passed):
                by_class.setdefault(p["class_name"], []).append(idx)
            suppressed_idxs = set()
            for cls, idxs in by_class.items():
                order = sorted(idxs, key=lambda i: (-passed[i]["confidence"], i))
                taken = set()
                for pos in order:
                    if pos in taken:
                        continue
                    for later in order[order.index(pos) + 1:]:
                        if later in taken:
                            continue
                        if iou(passed[pos]["corners"],
                               passed[later]["corners"]) >= iou_threshold:
                            taken.add(later)
                            suppressed_idxs.add(later)
                suppressed_idxs |= taken
            kept_parsed = [p for i, p in enumerate(passed)
                           if i not in suppressed_idxs]
            suppressed = len(suppressed_idxs)

            # Cap at max_detections: keep top-confidence overall,
            # deterministic order for reporting (class, then confidence).
            if len(kept_parsed) > max_detections:
                trimmed = sorted(
                    enumerate(kept_parsed),
                    key=lambda e: (-e[1]["confidence"], e[1]["class_name"], e[0]))
                drop = {e[0] for e in trimmed[max_detections:]}
                suppressed += len(drop)
                kept_parsed = [p for i, p in enumerate(kept_parsed)
                               if i not in drop]

            self._report_count += 1
            report_id = f"dr-{self._report_count}"
            detections: List[Detection] = []
            for n, p in enumerate(kept_parsed, start=1):
                det_id = f"det-{n}"
                digest = self._digest("detection", {
                    "image_id": image_id,
                    "detection_id": det_id,
                    "class_name": p["class_name"],
                    "box": list(p["box"]),
                    "confidence": p["confidence"],
                })
                detections.append(Detection(
                    detection_id=det_id,
                    class_name=p["class_name"],
                    box=p["box"],
                    confidence=p["confidence"],
                    digest=digest,
                ))
            body = {
                "report_id": report_id,
                "image_id": image_id,
                "detections": [d.as_dict() for d in detections],
                "kept": len(detections),
                "suppressed": suppressed,
            }
            report = DetectionReport(
                report_id=report_id,
                image_id=image_id,
                detections=tuple(detections),
                kept=len(detections),
                suppressed=suppressed,
                digest=self._digest("detection-report", body),
            )
            self._reports[report_id] = report
            self._audit("detected", seq, {
                "report_id": report_id,
                "image_id": image_id,
                "kept": report.kept,
                "suppressed": report.suppressed,
                "digest": report.digest,
            })
            return report

    def track(self, image_id: str, report_id: str, seq: int,
              min_iou: float = DEFAULT_TRACK_MIN_IOU,
              max_age: int = DEFAULT_TRACK_MAX_AGE) -> TrackReport:
        """Associate a detection report with live tracks; return tracks."""
        with self._lock:
            self._next_seq(seq)
            if not isinstance(image_id, str) or not image_id:
                raise TrackError("image_id must be a non-empty str")
            report = self._reports.get(report_id)
            if report is None:
                raise TrackError(f"unknown report_id {report_id!r}")
            if not _is_real_float(min_iou) or not 0.0 < min_iou <= 1.0:
                raise TrackError("min_iou must be a finite float in (0, 1]")
            if isinstance(max_age, bool) or not isinstance(max_age, int) \
                    or max_age < 0:
                raise TrackError("max_age must be a non-negative int")

            dets = list(report.detections)
            det_corners = [_decode_corners(*d.box) for d in dets]

            # Greedy IoU assignment, same class only: highest IoU pair
            # first, deterministic tie-break by (det id, track id).
            live = {tid: row for tid, row in self._tracks.items()}
            pairs: List[Tuple[float, int, str]] = []
            for di, d in enumerate(dets):
                for tid, row in live.items():
                    if row["class_name"] != d.class_name:
                        continue
                    value = iou(det_corners[di],
                                _decode_corners(*row["box"]))
                    if value >= min_iou:
                        pairs.append((value, di, tid))
            pairs.sort(key=lambda p: (-p[0], p[1], p[2]))

            used_det = set()
            used_track = set()
            matched = 0
            for value, di, tid in pairs:
                if di in used_det or tid in used_track:
                    continue
                used_det.add(di)
                used_track.add(tid)
                row = self._tracks[tid]
                row["box"] = dets[di].box
                row["confidence"] = dets[di].confidence
                row["age"] = 0
                row["frames_seen"] += 1
                matched += 1

            # Age un-matched tracks; expire past max_age.
            expired = 0
            for tid, row in list(self._tracks.items()):
                if tid not in used_track:
                    row["age"] += 1
                    if row["age"] > max_age:
                        del self._tracks[tid]
                        expired += 1

            # Spawn new tracks for un-matched detections.
            spawned = 0
            for di, d in enumerate(dets):
                if di in used_det:
                    continue
                self._track_seq += 1
                tid = f"trk-{self._track_seq}"
                self._tracks[tid] = {
                    "class_name": d.class_name,
                    "box": d.box,
                    "confidence": d.confidence,
                    "age": 0,
                    "frames_seen": 1,
                }
                spawned += 1

            self._report_count += 1
            tr_report_id = f"tr-{self._report_count}"
            tracks = tuple(
                Track(track_id=tid,
                      class_name=row["class_name"],
                      box=row["box"],
                      confidence=row["confidence"],
                      age=row["age"],
                      frames_seen=row["frames_seen"])
                for tid, row in sorted(self._tracks.items()))
            body = {
                "report_id": tr_report_id,
                "image_id": image_id,
                "tracks": [t.as_dict() for t in tracks],
                "matched": matched,
                "spawned": spawned,
                "expired": expired,
            }
            report = TrackReport(
                report_id=tr_report_id,
                image_id=image_id,
                tracks=tracks,
                matched=matched,
                spawned=spawned,
                expired=expired,
                digest=self._digest("track-report", body),
            )
            self._audit("tracked", seq, {
                "report_id": tr_report_id,
                "image_id": image_id,
                "matched": matched,
                "spawned": spawned,
                "expired": expired,
                "digest": report.digest,
            })
            return report

    def count(self, report_id: str, seq: int) -> CountReport:
        """Per-class tallies from a pinned ``DetectionReport``."""
        with self._lock:
            self._next_seq(seq)
            report = self._reports.get(report_id)
            if report is None:
                raise TrackError(f"unknown report_id {report_id!r}")
            tally: Dict[str, int] = {}
            for d in report.detections:
                tally[d.class_name] = tally.get(d.class_name, 0) + 1
            counts = tuple(sorted(tally.items()))
            self._report_count += 1
            count_id = f"cr-{self._report_count}"
            body = {
                "report_id": count_id,
                "source_report_id": report_id,
                "counts": [list(pair) for pair in counts],
                "total": sum(tally.values()),
            }
            result = CountReport(
                report_id=count_id,
                source_report_id=report_id,
                counts=counts,
                total=sum(tally.values()),
                digest=self._digest("count-report", body),
            )
            self._audit("counted", seq, {
                "report_id": count_id,
                "source_report_id": report_id,
                "total": result.total,
                "digest": result.digest,
            })
            return result

    # -- views -------------------------------------------------------------

    def report(self, report_id: str) -> DetectionReport:
        report = self._reports.get(report_id)
        if report is None:
            raise TrackError(f"unknown report_id {report_id!r}")
        return report

    def report_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._reports.keys())

    def track_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tracks.keys()))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)

    def reset_tracks(self, seq: int) -> None:
        """Clear all live tracks (fail-closed host operation)."""
        with self._lock:
            self._next_seq(seq)
            self._tracks.clear()
            self._track_seq = 0
            self._audit("rejected", seq, {"action": "tracks-reset"})


# ---------------------------------------------------------------------------
# Audit event shape helper.
# ---------------------------------------------------------------------------

def object_detector_audit_event(kind: str, seq: int,
                                detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module (validation only)."""
    allowed = {"detected", "tracked", "counted", "rejected"}
    if kind not in allowed:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError(f"seq must be a positive int, got {seq!r}")
    if not isinstance(detail, Mapping):
        raise BadCandidateError("detail must be a mapping")
    return {
        "schema": AUDIT_SCHEMA,
        "module": OBJECT_DETECTOR_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Self-check.
# ---------------------------------------------------------------------------

def main() -> None:
    det = ObjectDetector()
    cands = [
        {"class_name": "car", "box": (0.5, 0.5, 0.2, 0.2),
         "confidence": 0.90},
        {"class_name": "car", "box": (0.51, 0.51, 0.2, 0.2),
         "confidence": 0.80},
        {"class_name": "person", "box": (0.2, 0.2, 0.1, 0.3),
         "confidence": 0.95},
        {"class_name": "dog", "box": (0.8, 0.8, 0.1, 0.1),
         "confidence": 0.10},
    ]
    rep = det.detect("frame-1", cands, seq=1)
    # kept: top car + person; suppressed: NMS-duplicate car (1).
    # The dog is dropped by the confidence filter, not NMS.
    assert rep.kept == 2 and rep.suppressed == 1, rep.as_dict()
    tr = det.track("frame-1", rep.report_id, seq=2)
    assert tr.spawned == 2 and tr.matched == 0, tr.as_dict()
    cnt = det.count(rep.report_id, seq=3)
    assert cnt.total == 2 and dict(cnt.counts) == {"car": 1, "person": 1}
    # Track again on the same report: all match.
    tr2 = det.track("frame-1", rep.report_id, seq=4)
    assert tr2.matched == 2 and tr2.spawned == 0, tr2.as_dict()
    print("object-detector OK: detect NMS, track associate, count")


if __name__ == "__main__":
    main()
