"""Document scanner: simulated edge/corner detection and enhancement bookkeeping.

Simulated interface (OpenCV/CamScanner lineage). This module books
document *processing decisions* on host-reported images: it pins corner
coordinates, enhancement pipelines, and crop geometry with ``sha256:``
digest pins. It performs no image I/O and no real edge detection —
pins bind the *reported* geometry, and a frozen audit trail records
every mutation.

Honest scope: ``corners`` cannot prove a document is actually in the
image (GIGO boundary); ``enhance`` pins the declared pipeline, not the
pixel output; ``crop`` pins the reported quadrilateral warp params.
Pair with a real edge detector for production use.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
DOC_SCANNER_VERSION = "doc-scanner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.doc-scanner.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned enhancement operation vocabulary (CamScanner/Adobe Scan lineage).
ENHANCE_OPS = (
    "grayscale",
    "deskew",
    "denoise",
    "contrast",
    "sharpen",
    "binarize",
    "shadow_remove",
)

#: Max image dimension in px (guardrail against absurd inputs).
MAX_DIM_PX = 16384

#: Max images retained in the ledger (guardrail).
MAX_IMAGES = 10000


def _sha256_hex(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _pin(obj: Any) -> str:
    return _sha256_hex(jcs_canonical_json(obj))


class DocScannerError(Exception):
    """Base fail-closed document-scanner error."""


class UnknownImageError(DocScannerError):
    """No image registered under this id."""


class DuplicateImageError(DocScannerError):
    """An image with this id is already registered."""


class BadGeometryError(DocScannerError):
    """Corner polygon is degenerate, out of bounds, or wrong shape."""


class BadOperationError(DocScannerError):
    """Unknown or malformed enhancement operation."""


class ValidationError(DocScannerError):
    """A plain input-validation refusal."""


class SeqOrderError(DocScannerError):
    """Caller seq did not strictly increase."""


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"seq must be >= 0, got {value}")
    return value


def _check_point(pt: Any, width: int, height: int) -> Tuple[float, float]:
    if not isinstance(pt, (tuple, list)) or len(pt) != 2:
        raise BadGeometryError("corner must be an (x, y) pair")
    x, y = pt
    for v, name in ((x, "x"), (y, "y")):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise BadGeometryError(f"corner {name} must be a number")
        if not math.isfinite(v):
            raise BadGeometryError(f"corner {name} must be finite")
    if not (0.0 <= x <= width) or not (0.0 <= y <= height):
        raise BadGeometryError("corner lies outside the image bounds")
    return (float(x), float(y))


def _polygon_area(pts: Tuple[Tuple[float, float], ...]) -> float:
    area = 0.0
    for i in range(len(pts)):
        x0, y0 = pts[i]
        x1, y1 = pts[(i + 1) % len(pts)]
        area += x0 * y1 - x1 * y0
    return abs(area) / 2.0


@dataclass(frozen=True)
class Point:
    """Image coordinate in px."""

    x: float
    y: float

    def as_dict(self) -> Dict[str, Any]:
        return {"x": self.x, "y": self.y}


@dataclass(frozen=True)
class ImageRecord:
    """A registered scan candidate."""

    image_id: str
    width: int
    height: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "seq": self.seq,
            "pin": self.pin,
            "schema": SCHEMA_PIN,
            "version": DOC_SCANNER_VERSION,
        }


@dataclass(frozen=True)
class CornersRecord:
    """Detected document corners (tl, tr, br, bl) with geometry sanity."""

    image_id: str
    corners: Tuple[Point, Point, Point, Point]
    area_px2: float
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "corners": [c.as_dict() for c in self.corners],
            "area_px2": self.area_px2,
            "seq": self.seq,
            "pin": self.pin,
            "schema": SCHEMA_PIN,
            "version": DOC_SCANNER_VERSION,
        }


@dataclass(frozen=True)
class EnhanceRecord:
    """Declared enhancement pipeline for a scan."""

    image_id: str
    operations: Tuple[str, ...]
    strength: float
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "operations": list(self.operations),
            "strength": self.strength,
            "seq": self.seq,
            "pin": self.pin,
            "schema": SCHEMA_PIN,
            "version": DOC_SCANNER_VERSION,
        }


@dataclass(frozen=True)
class CropRecord:
    """Crop to a quadrilateral, with declared output size."""

    image_id: str
    corners: Tuple[Point, Point, Point, Point]
    out_width: int
    out_height: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "corners": [c.as_dict() for c in self.corners],
            "out_width": self.out_width,
            "out_height": self.out_height,
            "seq": self.seq,
            "pin": self.pin,
            "schema": SCHEMA_PIN,
            "version": DOC_SCANNER_VERSION,
        }


class DocScanner:
    """Simulated document-scanning ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: Dict[str, ImageRecord] = {}
        self._corners: Dict[str, CornersRecord] = {}
        self._enhance: Dict[str, EnhanceRecord] = {}
        self._crops: Dict[str, CropRecord] = {}
        self._last_seq = -1
        self._audit: Tuple[Dict[str, Any], ...] = ()

    # -- internals -----------------------------------------------------
    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _note(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        event = {
            "kind": kind,
            "seq": seq,
            "version": DOC_SCANNER_VERSION,
            "audit_schema": AUDIT_SCHEMA,
            "detail": dict(detail),
        }
        self._audit = self._audit + (event,)

    def _get_image(self, image_id: str) -> ImageRecord:
        rec = self._images.get(image_id)
        if rec is None:
            raise UnknownImageError(f"unknown image: {image_id!r}")
        return rec

    # -- image registration --------------------------------------------
    def register_image(
        self, image_id: str, width: int, height: int, seq: int
    ) -> ImageRecord:
        """Register a scan candidate with pixel dimensions."""
        with self._lock:
            if not isinstance(image_id, str) or not image_id:
                raise ValidationError("image_id must be a non-empty string")
            for dim, name in ((width, "width"), (height, "height")):
                if isinstance(dim, bool) or not isinstance(dim, int):
                    raise ValidationError(f"{name} must be an int")
                if not (1 <= dim <= MAX_DIM_PX):
                    raise ValidationError(
                        f"{name} must be in [1, {MAX_DIM_PX}]"
                    )
            if image_id in self._images:
                raise DuplicateImageError(f"image already registered: {image_id!r}")
            if len(self._images) >= MAX_IMAGES:
                raise ValidationError("image ledger is full")
            self._claim_seq(seq)
            pin = _pin(["image", image_id, width, height])
            rec = ImageRecord(
                image_id=image_id,
                width=width,
                height=height,
                seq=seq,
                pin=pin,
            )
            self._images[image_id] = rec
            self._note("image-registered", seq, {"image_id": image_id, "pin": pin})
            return rec

    # -- corners ---------------------------------------------------------
    def corners(
        self,
        image_id: str,
        quad: Tuple[Any, Any, Any, Any],
        seq: int,
        *,
        hint: str = "edge",
    ) -> CornersRecord:
        """Pin document corners (tl, tr, br, bl) for a registered image.

        The host reports the corner geometry detected by its edge
        detector; this module validates the quadrilateral and pins it.
        """
        with self._lock:
            img = self._get_image(image_id)
            if not isinstance(hint, str) or not hint:
                raise ValidationError("hint must be a non-empty string")
            if not isinstance(quad, (tuple, list)) or len(quad) != 4:
                raise BadGeometryError("quad must hold exactly 4 corners")
            pts = tuple(
                Point(*_check_point(p, img.width, img.height)) for p in quad
            )
            area = _polygon_area(tuple((p.x, p.y) for p in pts))
            if area <= 0.0:
                raise BadGeometryError("corner polygon is degenerate")
            self._claim_seq(seq)
            pin = _pin(
                [
                    "corners",
                    image_id,
                    hint,
                    [[p.x, p.y] for p in pts],
                ]
            )
            rec = CornersRecord(
                image_id=image_id,
                corners=(pts[0], pts[1], pts[2], pts[3]),
                area_px2=area,
                seq=seq,
                pin=pin,
            )
            self._corners[image_id] = rec
            self._note("corners-pinned", seq, {"image_id": image_id, "pin": pin})
            return rec

    # -- enhance ---------------------------------------------------------
    def enhance(
        self,
        image_id: str,
        operations: Tuple[str, ...],
        seq: int,
        *,
        strength: float = 1.0,
    ) -> EnhanceRecord:
        """Declare the enhancement pipeline for a scan."""
        with self._lock:
            self._get_image(image_id)
            if not isinstance(operations, (tuple, list)) or not operations:
                raise BadOperationError("operations must be non-empty")
            for op in operations:
                if op not in ENHANCE_OPS:
                    raise BadOperationError(f"unknown operation: {op!r}")
            if isinstance(strength, bool) or not isinstance(strength, (int, float)):
                raise BadOperationError("strength must be a number")
            if not math.isfinite(strength) or not (0.0 < strength <= 2.0):
                raise BadOperationError("strength must be in (0, 2]")
            self._claim_seq(seq)
            ops = tuple(operations)
            pin = _pin(["enhance", image_id, list(ops), float(strength)])
            rec = EnhanceRecord(
                image_id=image_id,
                operations=ops,
                strength=float(strength),
                seq=seq,
                pin=pin,
            )
            self._enhance[image_id] = rec
            self._note("enhance-declared", seq, {"image_id": image_id, "pin": pin})
            return rec

    # -- crop ------------------------------------------------------------
    def crop(
        self,
        image_id: str,
        seq: int,
        *,
        quad: Optional[Tuple[Any, Any, Any, Any]] = None,
        out_width: int = 0,
        out_height: int = 0,
    ) -> CropRecord:
        """Crop the image to the pinned corners (or an explicit quad)."""
        with self._lock:
            img = self._get_image(image_id)
            if quad is None:
                corners_rec = self._corners.get(image_id)
                if corners_rec is None:
                    raise BadGeometryError(
                        "no corners pinned for image; pass quad explicitly"
                    )
                pts = corners_rec.corners
            else:
                if not isinstance(quad, (tuple, list)) or len(quad) != 4:
                    raise BadGeometryError("quad must hold exactly 4 corners")
                pts = tuple(
                    Point(*_check_point(p, img.width, img.height)) for p in quad
                )
                area = _polygon_area(tuple((p.x, p.y) for p in pts))
                if area <= 0.0:
                    raise BadGeometryError("corner polygon is degenerate")
            for dim, name in ((out_width, "out_width"), (out_height, "out_height")):
                if isinstance(dim, bool) or not isinstance(dim, int):
                    raise ValidationError(f"{name} must be an int")
                if not (1 <= dim <= MAX_DIM_PX):
                    raise ValidationError(
                        f"{name} must be in [1, {MAX_DIM_PX}]"
                    )
            self._claim_seq(seq)
            pin = _pin(
                [
                    "crop",
                    image_id,
                    [[p.x, p.y] for p in pts],
                    out_width,
                    out_height,
                ]
            )
            rec = CropRecord(
                image_id=image_id,
                corners=(pts[0], pts[1], pts[2], pts[3]),
                out_width=out_width,
                out_height=out_height,
                seq=seq,
                pin=pin,
            )
            self._crops[image_id] = rec
            self._note("crop-pinned", seq, {"image_id": image_id, "pin": pin})
            return rec

    # -- views -----------------------------------------------------------
    def image(self, image_id: str) -> ImageRecord:
        with self._lock:
            return self._get_image(image_id)

    def image_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._images)

    def corners_for(self, image_id: str) -> Optional[CornersRecord]:
        with self._lock:
            return self._corners.get(image_id)

    def enhance_for(self, image_id: str) -> Optional[EnhanceRecord]:
        with self._lock:
            return self._enhance.get(image_id)

    def crop_for(self, image_id: str) -> Optional[CropRecord]:
        with self._lock:
            return self._crops.get(image_id)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return self._audit


def doc_scanner_audit_event(
    kind: str, seq: int, detail: Mapping[str, Any]
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for document-scanning activity."""
    valid = {
        "image-registered",
        "corners-pinned",
        "enhance-declared",
        "crop-pinned",
        "rejected",
    }
    if kind not in valid:
        raise ValidationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {
        "kind": kind,
        "seq": seq,
        "version": DOC_SCANNER_VERSION,
        "audit_schema": AUDIT_SCHEMA,
        "detail": dict(detail),
    }


def main() -> None:
    scanner = DocScanner()
    img = scanner.register_image("img-1", 1200, 1600, 1)
    assert img.pin.startswith("sha256:")
    quad = ((100, 120), (1100, 140), (1080, 1500), (80, 1480))
    corners = scanner.corners("img-1", quad, 2)
    assert corners.area_px2 > 0
    enh = scanner.enhance("img-1", ("grayscale", "deskew", "contrast"), 3)
    assert enh.operations == ("grayscale", "deskew", "contrast")
    crop = scanner.crop("img-1", 4, out_width=2480, out_height=3508)
    assert crop.out_width == 2480
    events = doc_scanner_audit_event("corners-pinned", 2, {"pin": corners.pin})
    assert events["audit_schema"] == AUDIT_SCHEMA
    print(
        "doc-scanner OK: register, corners, enhance, crop, pins, "
        f"audit ({len(scanner.audit_log())} events)"
    )


if __name__ == "__main__":
    main()
