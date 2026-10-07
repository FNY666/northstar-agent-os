"""Image transform contract (PNG/JPEG/WebP/GIF/BMP/TIFF bookkeeping).

Research motivation: agents routinely need to normalize images -- resize
avatars, convert uploads to a canonical format, strip metadata -- and every
step is a place where sloppy bookkeeping corrupts data silently (float
dimensions, lossy quality applied to PNG, upscaling beyond sane bounds,
guessing the format from a filename).

This module pins the deterministic bookkeeping half of that shape:

- ``ImageProcessor`` -- a registry of *declared* image properties. It
  decodes no pixels; the caller reports width/height/format and the
  module pins them. ``register()`` pins an image, ``resize()`` issues a
  frozen ``ResizeRecord`` for a target size, ``format()`` issues a frozen
  ``FormatRecord`` for a target container, ``metadata()`` re-reads the
  pinned record.
- ``image_processor_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``registered`` / ``resized`` / ``converted`` /
  ``metadata-read`` / ``rejected``); ids, digests, and dimensions only,
  never pixel bytes or EXIF values.

Pinned contracts:

- Formats: ``png``, ``jpeg``, ``webp``, ``gif``, ``bmp``, ``tiff``.
  Anything else is refused fail-closed; ``format()`` to the image's own
  format is refused (a no-op conversion is a lie of bookkeeping).
- Resize methods: ``nearest``, ``bilinear``, ``bicubic``, ``lanczos``.
- Quality is an int in [1, 100] and only applies to lossy containers
  (``jpeg``, ``webp``); passing a quality for a lossless target is
  refused.
- Dimensions are ints in [1, 16384]; bools, floats, NaN/inf, and
  out-of-range values are refused fail-closed.
- Digest pins are ``sha256:`` over type-tagged canonical bodies (bool !=
  int), so identical declarations replay to identical pins.

Fail-closed edges:

- Unknown image ids raise ``UnknownImageError`` (never fabricated).
- Duplicate image ids raise ``DuplicateImageError`` (never recycled).
- Non-positive / oversized dimensions, unknown formats or methods,
  same-format conversion, and non-increasing caller seqs are refused.
- A failed mutation still consumes its seq (fail-closed ledger position,
  same discipline as the batch-21 ``rbac_engine`` module).

Honest scope:

- This module books *declared* properties. It cannot verify that the
  pixels behind ``img-1`` are really 800x600 PNG; ``resize()`` proves the
  transform contract was booked correctly, never that pixels were
  resampled. Pair with a real codec (Pillow, libvips) for production I/O.
- ``format()`` pins the declared output container; it cannot prove the
  encoder honored the quality setting.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple

IMAGE_PROCESSOR_VERSION = "image-processor.v1"
SCHEMA_PIN = "northstar.image-processor.v1"

#: Pinned container vocabulary.
FORMATS = ("png", "jpeg", "webp", "gif", "bmp", "tiff")

#: Lossy containers (quality is meaningful only for these).
LOSSY_FORMATS = ("jpeg", "webp")

#: Pinned resampling method vocabulary.
RESIZE_METHODS = ("nearest", "bilinear", "bicubic", "lanczos")

#: Hard caps on declared dimensions (16K).
_MIN_DIM = 1
_MAX_DIM = 16384

_IMAGE_AUDIT_KINDS = (
    "registered",
    "resized",
    "converted",
    "metadata-read",
    "rejected",
)


class ImageError(ValueError):
    """Base fail-closed error for the image processor."""


class UnknownImageError(ImageError):
    """The image id is not in the registry."""


class DuplicateImageError(ImageError):
    """The image id is already registered."""


class BadDimensionError(ImageError):
    """A width/height is not an int in [1, 16384]."""


class UnknownFormatError(ImageError):
    """The format is not in the pinned vocabulary."""


class UnknownMethodError(ImageError):
    """The resize method is not in the pinned vocabulary."""


class BadQualityError(ImageError):
    """Quality is not an int in [1, 100], or was given for a lossless target."""


class NoopTransformError(ImageError):
    """A transform that would change nothing (same format)."""


class SeqOrderError(ImageError):
    """The caller seq did not strictly increase."""


def _check_seq_value(seq: int) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError("seq must be a positive int")


def _encode_tagged(value: object) -> bytes:
    """Type-tagged canonical encoding (bool != int)."""
    if isinstance(value, bool):
        return b"b1" if value else b"b0"
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise ImageError("refused |n| >= 2**53 (JCS float-loss boundary)")
        return b"i" + str(value).encode("ascii")
    if isinstance(value, str):
        return b"s" + value.encode("utf-8")
    if value is None:
        return b"n"
    if isinstance(value, (tuple, list)):
        return b"l" + b"".join(_encode_tagged(v) for v in value)
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return b"m" + b"".join(
            _encode_tagged(k) + _encode_tagged(v) for k, v in items
        )
    raise ImageError(f"unpinable type for digest: {type(value).__name__}")


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    h = hashlib.sha256()
    for key, value in parts:
        h.update(_encode_tagged(key))
        h.update(b"\x00")
        h.update(_encode_tagged(value))
        h.update(b"\xff")
    return "sha256:" + h.hexdigest()


def _check_dimensions(width: int, height: int) -> None:
    for name, dim in (("width", width), ("height", height)):
        if isinstance(dim, bool) or not isinstance(dim, int):
            raise BadDimensionError(f"{name} must be an int, got {type(dim).__name__}")
        if not (_MIN_DIM <= dim <= _MAX_DIM):
            raise BadDimensionError(
                f"{name} out of bounds [{_MIN_DIM}, {_MAX_DIM}]: {dim}"
            )


def _check_format(fmt: str) -> None:
    if not isinstance(fmt, str) or fmt not in FORMATS:
        raise UnknownFormatError(f"unknown format: {fmt!r}")


@dataclass(frozen=True)
class ImageRecord:
    """Pinned declaration of a registered image."""

    image_id: str
    width: int
    height: int
    format: str
    seq: int
    source_digest: str
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "seq": self.seq,
            "source_digest": self.source_digest,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class ResizeRecord:
    """Pinned resize contract for a registered image."""

    image_id: str
    from_width: int
    from_height: int
    to_width: int
    to_height: int
    method: str
    scale_x_num: int
    scale_x_den: int
    scale_y_num: int
    scale_y_den: int
    seq: int
    source_pin: str
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "image_id": self.image_id,
            "from_width": self.from_width,
            "from_height": self.from_height,
            "to_width": self.to_width,
            "to_height": self.to_height,
            "method": self.method,
            "scale_x": (self.scale_x_num, self.scale_x_den),
            "scale_y": (self.scale_y_num, self.scale_y_den),
            "seq": self.seq,
            "source_pin": self.source_pin,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class FormatRecord:
    """Pinned format-conversion contract for a registered image."""

    image_id: str
    from_format: str
    to_format: str
    quality: Optional[int]
    seq: int
    source_pin: str
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "image_id": self.image_id,
            "from_format": self.from_format,
            "to_format": self.to_format,
            "quality": self.quality,
            "seq": self.seq,
            "source_pin": self.source_pin,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class MetadataRecord:
    """Re-read of the pinned record for a registered image."""

    image_id: str
    width: int
    height: int
    format: str
    pixel_count: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "pixel_count": self.pixel_count,
            "pin": self.pin,
        }


class ImageProcessor:
    """Registry of declared image properties plus transform contracts."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: Dict[str, ImageRecord] = {}
        self._last_seq = 0

    def _check_seq(self, seq: int) -> None:
        _check_seq_value(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq

    def _require_image(self, image_id: str) -> ImageRecord:
        rec = self._images.get(image_id)
        if rec is None:
            raise UnknownImageError(f"unknown image: {image_id!r}")
        return rec

    def register(
        self,
        image_id: str,
        width: int,
        height: int,
        format: str,
        seq: int,
        source_digest: str = "",
    ) -> ImageRecord:
        """Pin a declared image into the registry."""
        with self._lock:
            self._check_seq(seq)
            if not isinstance(image_id, str) or not image_id:
                raise ImageError("image_id must be a non-empty str")
            if image_id in self._images:
                raise DuplicateImageError(f"duplicate image: {image_id!r}")
            _check_dimensions(width, height)
            _check_format(format)
            if not isinstance(source_digest, str):
                raise ImageError("source_digest must be str")
            pin = _digest_tagged(
                (
                    ("image_id", image_id),
                    ("width", width),
                    ("height", height),
                    ("format", format),
                    ("source_digest", source_digest),
                    ("module", IMAGE_PROCESSOR_VERSION),
                )
            )
            rec = ImageRecord(
                image_id=image_id,
                width=width,
                height=height,
                format=format,
                seq=seq,
                source_digest=source_digest,
                pin=pin,
            )
            self._images[image_id] = rec
            return rec

    def resize(
        self,
        image_id: str,
        width: int,
        height: int,
        seq: int,
        method: str = "bilinear",
    ) -> ResizeRecord:
        """Issue a frozen resize contract for a registered image."""
        with self._lock:
            self._check_seq(seq)
            src = self._require_image(image_id)
            _check_dimensions(width, height)
            if not isinstance(method, str) or method not in RESIZE_METHODS:
                raise UnknownMethodError(f"unknown resize method: {method!r}")
            if width == src.width and height == src.height:
                raise NoopTransformError("resize to identical dimensions is a no-op")
            import math

            gx, gy = math.gcd(width, src.width), math.gcd(height, src.height)
            scale_x_num, scale_x_den = width // gx, src.width // gx
            scale_y_num, scale_y_den = height // gy, src.height // gy
            pin = _digest_tagged(
                (
                    ("image_id", image_id),
                    ("from", (src.width, src.height)),
                    ("to", (width, height)),
                    ("method", method),
                    ("source_pin", src.pin),
                    ("seq", seq),
                    ("module", IMAGE_PROCESSOR_VERSION),
                )
            )
            return ResizeRecord(
                image_id=image_id,
                from_width=src.width,
                from_height=src.height,
                to_width=width,
                to_height=height,
                method=method,
                scale_x_num=scale_x_num,
                scale_x_den=scale_x_den,
                scale_y_num=scale_y_num,
                scale_y_den=scale_y_den,
                seq=seq,
                source_pin=src.pin,
                pin=pin,
            )

    def format(
        self,
        image_id: str,
        target_format: str,
        seq: int,
        quality: Optional[int] = None,
    ) -> FormatRecord:
        """Issue a frozen format-conversion contract for a registered image."""
        with self._lock:
            self._check_seq(seq)
            src = self._require_image(image_id)
            _check_format(target_format)
            if target_format == src.format:
                raise NoopTransformError(
                    f"image is already {src.format}; conversion is a no-op"
                )
            if target_format in LOSSY_FORMATS:
                if quality is not None and (
                    isinstance(quality, bool)
                    or not isinstance(quality, int)
                    or not (1 <= quality <= 100)
                ):
                    raise BadQualityError("quality must be an int in [1, 100]")
            elif quality is not None:
                raise BadQualityError(
                    f"quality is meaningless for lossless target {target_format!r}"
                )
            pin = _digest_tagged(
                (
                    ("image_id", image_id),
                    ("from_format", src.format),
                    ("to_format", target_format),
                    ("quality", quality),
                    ("source_pin", src.pin),
                    ("seq", seq),
                    ("module", IMAGE_PROCESSOR_VERSION),
                )
            )
            return FormatRecord(
                image_id=image_id,
                from_format=src.format,
                to_format=target_format,
                quality=quality,
                seq=seq,
                source_pin=src.pin,
                pin=pin,
            )

    def metadata(self, image_id: str, seq: int) -> MetadataRecord:
        """Re-read the pinned record for a registered image."""
        with self._lock:
            self._check_seq(seq)
            src = self._require_image(image_id)
            return MetadataRecord(
                image_id=image_id,
                width=src.width,
                height=src.height,
                format=src.format,
                pixel_count=src.width * src.height,
                pin=src.pin,
            )

    def image(self, image_id: str) -> ImageRecord:
        with self._lock:
            return self._require_image(image_id)

    def image_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._images))


def image_processor_audit_event(
    kind: str,
    seq: int,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for image processor activity.

    Carries ids, digests, and dimensions only -- never pixel bytes or
    EXIF values.
    """
    if kind not in _IMAGE_AUDIT_KINDS:
        raise ImageError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise ImageError("seq must be a positive int")
    if not isinstance(detail, str):
        raise ImageError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": IMAGE_PROCESSOR_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    p = ImageProcessor()
    rec = p.register("img-1", 800, 600, "png", 1, source_digest="sha256:abc")
    assert rec.width == 800 and rec.format == "png"
    assert rec.pin.startswith("sha256:")
    rz = p.resize("img-1", 400, 300, 2)
    assert (rz.to_width, rz.to_height) == (400, 300)
    assert (rz.scale_x_num, rz.scale_x_den) == (1, 2)
    fm = p.format("img-1", "jpeg", 3, quality=85)
    assert fm.quality == 85
    md = p.metadata("img-1", 4)
    assert md.pixel_count == 480000 and md.pin == rec.pin
    evt = image_processor_audit_event("resized", 1)
    assert evt["schema"] == SCHEMA_PIN
    print("image-processor OK: register, resize, format, metadata, audit")


if __name__ == "__main__":
    main()
