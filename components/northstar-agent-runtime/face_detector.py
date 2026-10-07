"""Face detection interface (deterministic boxes, landmarks, attributes).

Research motivation: face detection is the oldest vision primitive on the
agent-runtime roadmap -- every "see the human" feature (identity check-in,
attention tracking, liveness, meeting diarization) bottoms out in the
same bookkeeping shape the industry converged on (OpenCV Haar/DNN,
dlib HOG, MediaPipe BlazeFace, InsightFace RetinaFace):

- *detection*: candidate regions as pixel boxes ``(x, y, w, h)`` with a
  confidence score in ``[0, 1]``; box coords are integers (pixels), never
  floats;
- *landmarks*: named fiducial points (eyes, nose, mouth corners) inside
  the box, still integer pixel coordinates;
- *attributes*: pinned-vocabulary per-face descriptors (glasses, mask,
  age bucket) -- always host-reported guesses, never facts.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's vision plumbing speaks one dialect:

- ``FaceDetector`` -- owns the registered-image ledger, the box ledger,
  the landmark ledger, and the attribute ledger. ``register_image()``
  pins an image's dimensions, ``detect()`` records the host-reported
  boxes for it, ``landmarks()`` pins fiducial points for a box, and
  ``attributes()`` pins vocabulary-checked descriptors for a box.
- ``face_detector_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``image-registered`` / ``detected`` / ``landmarks-pinned`` /
  ``attributes-pinned`` / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- Image dimensions and box/landmark coordinates are ``int`` pixels --
  floats (and bools) are refused outright: there is no sub-pixel
  addressing in this ledger. The batch-5 JCS caveat applies only to the
  digest encoding, not to user values, because no float ever reaches a
  pin except confidence, which is ``f:``-tagged and NaN/inf-refused.
- Boxes must be fully inside the registered image (``x, y >= 0``,
  ``w, h > 0``, ``x + w <= width``, ``y + h <= height``); landmarks
  must be inside their box's rectangle. Detection quality is the
  host's job; geometric impossibility is not admitted.
- Confidence is a ``float`` (or ``int``) in ``[0, 1]``, finite --
  ``NaN``/``inf``/out-of-range are refused.
- Attribute names come from a closed vocabulary (``ATTRIBUTE_VOCAB``);
  unknown names are refused at pin time, never stored.
- Image ids and face ids are non-empty ``str``; duplicates refused.
- Mutating seqs are caller-supplied strictly increasing ints per
  instance; a failed mutation consumes its seq (fail-closed ledger
  position, matching the batch-21 ``rbac_engine`` discipline).

Honest scope:

- This module books *host-reported* boxes, landmarks, and attributes.
  It cannot verify that a box contains a face, that a landmark sits on
  an eye, or that an attribute describes the pictured person; a lying
  detector gets a lying ledger. The digests bind the *reported* values
  to the records, not the truth.
- Attributes are classifier outputs, not facts. ``attributes()`` pins
  what the host claimed (with the pinned vocabulary), never what is.
- ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return _hashlib.sha256(raw).hexdigest()

FACE_DETECTOR_VERSION = "face-detector.v1"
FACE_DETECTOR_SCHEMA = "northstar.face-detector.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

# dlib/InsightFace-flavored pinned landmark keys. Indexed points may
# accompany them, but these names are always available and spelled this
# way.
LANDMARK_KEYS = (
    "left_eye",
    "right_eye",
    "nose_tip",
    "mouth_left",
    "mouth_right",
    "chin",
)

# Closed attribute vocabulary. Values are pinned per name; unknown
# names are refused at pin time.
ATTRIBUTE_VOCAB = {
    "glasses": ("none", "eyeglasses", "sunglasses"),
    "mask": ("none", "mask"),
    "age_bucket": ("0-12", "13-19", "20-39", "40-59", "60+"),
    "gender_expression": ("masculine", "feminine", "unknown"),
    "head_pose": ("frontal", "profile", "tilted"),
}


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------


class FaceDetectorError(Exception):
    """Base fail-closed face-detector error."""


class DuplicateImageError(FaceDetectorError):
    """An image id was registered twice."""


class UnknownImageError(FaceDetectorError):
    """A mutation referenced an unregistered image id."""


class UnknownFaceError(FaceDetectorError):
    """A mutation referenced an unknown face id."""


class BadGeometryError(FaceDetectorError):
    """Coordinates, dimensions, or a box violate the pixel-int contract."""


class BadConfidenceError(FaceDetectorError):
    """Confidence is not a finite float/int in [0, 1]."""


class UnknownAttributeError(FaceDetectorError):
    """An attribute name or value is outside the pinned vocabulary."""


class SeqOrderError(FaceDetectorError):
    """A mutation seq did not strictly increase."""


class BadKindError(FaceDetectorError):
    """An audit event kind is not one of the fixed kinds."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _tagged(obj: Any) -> Any:
    """Type-tagged canonical encoding (bool != int != str != float).

    Floats are NaN/inf-refused; integral floats are tagged ``f:`` so a
    confidence of ``1.0`` never collides with the int ``1`` in a pin.
    """
    if isinstance(obj, bool):
        return "b:1" if obj else "b:0"
    if isinstance(obj, int):
        return f"i:{obj}"
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise FaceDetectorError("NaN/inf refused in digest encoding")
        return f"f:{obj!r}"
    if isinstance(obj, str):
        return f"s:{obj}"
    if obj is None:
        return "n"
    if isinstance(obj, (tuple, list)):
        return [_tagged(v) for v in obj]
    if isinstance(obj, Mapping):
        return {f"s:{k}": _tagged(v) for k, v in sorted(obj.items())}
    raise FaceDetectorError(f"unencodable value: {type(obj).__name__}")


def _pin(*parts: Any) -> str:
    """``sha256:`` digest pin over the type-tagged parts."""
    return "sha256:" + jcs_sha256_hex(_tagged(list(parts)))


def _require_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int, not bool")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _require_pixel(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadGeometryError(f"{name} must be an int pixel, not {type(value).__name__}")
    return value


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImageRecord:
    image_id: str
    width: int
    height: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": FACE_DETECTOR_SCHEMA,
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class FaceBox:
    face_id: str
    image_id: str
    x: int
    y: int
    w: int
    h: int
    confidence: float
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": FACE_DETECTOR_SCHEMA,
            "face_id": self.face_id,
            "image_id": self.image_id,
            "x": self.x,
            "y": self.y,
            "w": self.w,
            "h": self.h,
            "confidence": self.confidence,
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class LandmarkSet:
    face_id: str
    points: Tuple[Tuple[str, int, int], ...]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": FACE_DETECTOR_SCHEMA,
            "face_id": self.face_id,
            "points": [{"key": k, "x": x, "y": y} for k, x, y in self.points],
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class AttributeRecord:
    face_id: str
    attrs: Tuple[Tuple[str, str], ...]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": FACE_DETECTOR_SCHEMA,
            "face_id": self.face_id,
            "attrs": [{"name": n, "value": v} for n, v in self.attrs],
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class DetectionReport:
    image_id: str
    face_ids: Tuple[str, ...]
    face_count: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": FACE_DETECTOR_SCHEMA,
            "image_id": self.image_id,
            "face_ids": list(self.face_ids),
            "face_count": self.face_count,
            "seq": self.seq,
            "pin": self.pin,
        }


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

AUDIT_KINDS = (
    "image-registered",
    "detected",
    "landmarks-pinned",
    "attributes-pinned",
    "rejected",
)


def face_detector_audit_event(kind: str, *, seq: int, image_id: Optional[str] = None,
                              face_id: Optional[str] = None,
                              detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the face detector.

    ``seq`` is caller-supplied (the detector never mints its own).
    Coordinates and confidences never cross the audit boundary -- only
    ids, counts, and digest pins.
    """
    if kind not in AUDIT_KINDS:
        raise BadKindError(f"unknown audit kind: {kind!r}")
    seq = _require_seq(seq)
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "component": "face-detector",
        "version": FACE_DETECTOR_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if image_id is not None:
        event["image_id"] = image_id
    if face_id is not None:
        event["face_id"] = face_id
    if detail is not None:
        event["detail"] = dict(detail)
    return event


# ---------------------------------------------------------------------------
# the detector (ledger)
# ---------------------------------------------------------------------------


class FaceDetector:
    """Deterministic face-detection *bookkeeping* (simulated detector).

    Owns four ledgers: registered images, detected boxes, landmark
    sets, and attribute records. All mutation seqs are caller-supplied
    strictly increasing ints; a failed mutation still consumes its seq
    (fail-closed ledger position). RLock-guarded.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._images: Dict[str, ImageRecord] = {}
        self._boxes: Dict[str, FaceBox] = {}
        self._landmarks: Dict[str, LandmarkSet] = {}
        self._attributes: Dict[str, AttributeRecord] = {}
        self._face_counter = 0
        self._audit_log: Tuple[Dict[str, Any], ...] = ()

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        seq = _require_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})")
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **kwargs: Any) -> None:
        self._audit_log = self._audit_log + (
            face_detector_audit_event(kind, seq=seq, **kwargs),)

    @staticmethod
    def _norm_id(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value:
            raise FaceDetectorError(f"{name} must be a non-empty str")
        return value

    def _norm_confidence(self, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadConfidenceError(
                f"confidence must be a number in [0, 1], not {type(value).__name__}")
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise BadConfidenceError("confidence must be finite")
        conf = float(value)
        if not 0.0 <= conf <= 1.0:
            raise BadConfidenceError(f"confidence {conf!r} outside [0, 1]")
        return conf

    # -- images ----------------------------------------------------------

    def register_image(self, image_id: str, width: Any, height: Any,
                       seq: int) -> ImageRecord:
        """Pin an image's pixel dimensions into the ledger."""
        with self._lock:
            seq = self._claim_seq(seq)
            image_id = self._norm_id(image_id, "image_id")
            width = _require_pixel(width, "width")
            height = _require_pixel(height, "height")
            if width <= 0 or height <= 0:
                raise BadGeometryError("image dimensions must be positive")
            if image_id in self._images:
                raise DuplicateImageError(f"image already registered: {image_id!r}")
            pin = _pin("image", image_id, width, height)
            record = ImageRecord(image_id=image_id, width=width,
                                 height=height, seq=seq, pin=pin)
            self._images[image_id] = record
            self._audit("image-registered", seq, image_id=image_id,
                        detail={"pin": pin})
            return record

    # -- detection --------------------------------------------------------

    def detect(self, image_id: str,
               faces: Any, seq: int) -> DetectionReport:
        """Record the host-reported boxes for a registered image.

        ``faces`` is a list of ``(x, y, w, h, confidence)`` tuples.
        Returns a frozen ``DetectionReport``; individual boxes are
        retrievable via ``face()`` / ``faces_of()``.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            image_id = self._norm_id(image_id, "image_id")
            image = self._images.get(image_id)
            if image is None:
                raise UnknownImageError(f"unknown image: {image_id!r}")
            if not isinstance(faces, (list, tuple)):
                raise BadGeometryError("faces must be a list of (x, y, w, h, confidence)")
            face_ids = []
            for entry in faces:
                box = self._norm_box(image, entry)
                self._face_counter += 1
                face_id = f"face-{self._face_counter}"
                confidence = self._norm_confidence(box[4])
                pin = _pin("face", face_id, image_id,
                           box[0], box[1], box[2], box[3], confidence)
                record = FaceBox(face_id=face_id, image_id=image_id,
                                 x=box[0], y=box[1], w=box[2], h=box[3],
                                 confidence=confidence, seq=seq, pin=pin)
                self._boxes[face_id] = record
                face_ids.append(face_id)
            pin = _pin("detection", image_id, tuple(face_ids), seq)
            report = DetectionReport(image_id=image_id,
                                     face_ids=tuple(face_ids),
                                     face_count=len(face_ids), seq=seq, pin=pin)
            self._audit("detected", seq, image_id=image_id,
                        detail={"face_count": len(face_ids), "pin": pin})
            return report

    def _norm_box(self, image: ImageRecord, entry: Any) -> Tuple[int, int, int, int, Any]:
        if not isinstance(entry, (list, tuple)) or len(entry) != 5:
            raise BadGeometryError("each face must be (x, y, w, h, confidence)")
        x, y, w, h, confidence = entry
        x = _require_pixel(x, "x")
        y = _require_pixel(y, "y")
        w = _require_pixel(w, "w")
        h = _require_pixel(h, "h")
        if w <= 0 or h <= 0:
            raise BadGeometryError("box width/height must be positive")
        if x < 0 or y < 0:
            raise BadGeometryError("box origin must be non-negative")
        if x + w > image.width or y + h > image.height:
            raise BadGeometryError(
                f"box ({x},{y},{w},{h}) exceeds image {image.width}x{image.height}")
        return (x, y, w, h, confidence)

    # -- landmarks --------------------------------------------------------

    def landmarks(self, face_id: str, points: Any,
                  seq: int) -> LandmarkSet:
        """Pin fiducial points for a detected face.

        ``points`` maps landmark key (one of ``LANDMARK_KEYS``) or an
        ``idx-N`` free-form point to ``(x, y)`` pixel coordinates.
        Points must lie inside the face's box.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            face_id = self._norm_id(face_id, "face_id")
            box = self._boxes.get(face_id)
            if box is None:
                raise UnknownFaceError(f"unknown face: {face_id!r}")
            if not isinstance(points, Mapping) or not points:
                raise BadGeometryError("points must be a non-empty mapping")
            normalized = []
            for key, coord in points.items():
                normalized.append(self._norm_point(box, key, coord))
            normalized.sort(key=lambda p: p[0])
            pin = _pin("landmarks", face_id,
                       tuple((k, x, y) for k, x, y in normalized))
            record = LandmarkSet(face_id=face_id,
                                 points=tuple(normalized), seq=seq, pin=pin)
            self._landmarks[face_id] = record
            self._audit("landmarks-pinned", seq, face_id=face_id,
                        detail={"point_count": len(normalized), "pin": pin})
            return record

    def _norm_point(self, box: FaceBox, key: Any,
                    coord: Any) -> Tuple[str, int, int]:
        if not isinstance(key, str) or not key:
            raise BadGeometryError("landmark key must be a non-empty str")
        if key not in LANDMARK_KEYS and not (
                key.startswith("idx-") and key[4:].isdigit()):
            raise BadGeometryError(f"unknown landmark key: {key!r}")
        if not isinstance(coord, (list, tuple)) or len(coord) != 2:
            raise BadGeometryError(f"point {key!r} must be (x, y)")
        x = _require_pixel(coord[0], f"{key}.x")
        y = _require_pixel(coord[1], f"{key}.y")
        if not (box.x <= x < box.x + box.w and box.y <= y < box.y + box.h):
            raise BadGeometryError(
                f"landmark {key!r} ({x},{y}) outside box "
                f"({box.x},{box.y},{box.w},{box.h})")
        return (key, x, y)

    # -- attributes --------------------------------------------------------

    def attributes(self, face_id: str, attrs: Any,
                   seq: int) -> AttributeRecord:
        """Pin vocabulary-checked attribute descriptors for a face.

        ``attrs`` maps attribute name (one of ``ATTRIBUTE_VOCAB``) to a
        pinned value. Values are host-reported classifier guesses --
        pinned as claims, never as facts.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            face_id = self._norm_id(face_id, "face_id")
            if face_id not in self._boxes:
                raise UnknownFaceError(f"unknown face: {face_id!r}")
            if not isinstance(attrs, Mapping) or not attrs:
                raise UnknownAttributeError("attrs must be a non-empty mapping")
            normalized = []
            for name, value in attrs.items():
                if name not in ATTRIBUTE_VOCAB:
                    raise UnknownAttributeError(f"unknown attribute: {name!r}")
                if not isinstance(value, str) or value not in ATTRIBUTE_VOCAB[name]:
                    raise UnknownAttributeError(
                        f"value {value!r} not in vocabulary for {name!r}")
                normalized.append((name, value))
            normalized.sort(key=lambda p: p[0])
            pin = _pin("attributes", face_id, tuple(normalized))
            record = AttributeRecord(face_id=face_id,
                                     attrs=tuple(normalized), seq=seq, pin=pin)
            self._attributes[face_id] = record
            self._audit("attributes-pinned", seq, face_id=face_id,
                        detail={"attr_count": len(normalized), "pin": pin})
            return record

    # -- views --------------------------------------------------------------

    def image(self, image_id: str) -> ImageRecord:
        record = self._images.get(image_id)
        if record is None:
            raise UnknownImageError(f"unknown image: {image_id!r}")
        return record

    def face(self, face_id: str) -> FaceBox:
        record = self._boxes.get(face_id)
        if record is None:
            raise UnknownFaceError(f"unknown face: {face_id!r}")
        return record

    def faces_of(self, image_id: str) -> Tuple[FaceBox, ...]:
        return tuple(b for b in self._boxes.values() if b.image_id == image_id)

    def landmark_set(self, face_id: str) -> LandmarkSet:
        record = self._landmarks.get(face_id)
        if record is None:
            raise UnknownFaceError(f"no landmarks pinned for face: {face_id!r}")
        return record

    def attribute_set(self, face_id: str) -> AttributeRecord:
        record = self._attributes.get(face_id)
        if record is None:
            raise UnknownFaceError(f"no attributes pinned for face: {face_id!r}")
        return record

    def image_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._images))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return self._audit_log


# ---------------------------------------------------------------------------
# self-check
# ---------------------------------------------------------------------------


def main() -> None:
    det = FaceDetector()
    det.register_image("img-1", 640, 480, seq=1)
    report = det.detect("img-1", [(10, 20, 100, 120, 0.97)], seq=2)
    face_id = report.face_ids[0]
    det.landmarks(face_id, {"left_eye": (40, 60), "right_eye": (80, 60)}, seq=3)
    det.attributes(face_id, {"glasses": "eyeglasses", "mask": "none"}, seq=4)
    assert det.face(face_id).confidence == 0.97
    assert det.landmark_set(face_id).points[0][0] == "left_eye"
    assert det.attribute_set(face_id).attrs[0] == ("glasses", "eyeglasses")
    assert det.faces_of("img-1")[0].face_id == face_id
    print("face-detector OK: register, detect, landmarks, attributes")


if __name__ == "__main__":
    main()
