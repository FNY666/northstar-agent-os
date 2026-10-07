"""Image optimization contract (Cloudflare Polish / Mirage shaped, simulated).

Research motivation: image CDNs (Cloudflare Polish, Mirage) normalize
images at the edge -- recompress losslessly or lossily, convert to modern
containers (WebP/AVIF), resize to viewport bounds, and lazy-load
below-the-fold images. Each step is silent data corruption when the
bookkeeping is sloppy: quality applied to a lossless container, upscale
beyond the source, a lazy placeholder that lies about intrinsic size.

This module pins the deterministic bookkeeping half of that shape:

- ``ImageOptimization`` -- a registry of *declared* image properties
  (it decodes no pixels; the caller reports width/height/format).
  ``register()`` pins an image, ``optimize()`` books a Polish-style
  optimization decision (mode, quality, resize bounds, metadata
  stripping), ``format()`` books a container conversion, and ``lazy()``
  books a Mirage-style lazy-load directive (placeholder, intrinsic
  size, above-the-fold exemption).
- ``image_optimization_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``registered`` / ``optimized`` / ``converted`` /
  ``lazy-marked`` / ``rejected``); ids, digests, and dimensions only,
  never pixel bytes.

Pinned contracts:

- Formats: ``png``, ``jpeg``, ``webp``, ``gif``, ``bmp``, ``tiff``,
  ``avif``. Anything else is refused fail-closed. ``avif`` is accepted
  as a target only (it is a modern delivery container; registering an
  avif source is allowed too -- the vocabulary is shared).
- Optimize modes: ``lossless``, ``lossy`` (Cloudflare Polish modes).
  ``lossy`` requires a quality in [1, 100] (defaults to 85);
  ``lossless`` refuses any quality value.
- Resize bounds (``max_width`` / ``max_height``) are optional ints in
  [1, 16384]; the booked target dims are the aspect-fit of the source
  into the bounds and never upscale beyond the source dims.
- ``format()`` to the image's own format is refused (a no-op
  conversion is a lie of bookkeeping); quality is allowed only for
  lossy targets (``jpeg``, ``webp``, ``avif``).
- Lazy placeholders: ``blur``, ``color``, ``none`` (Mirage shapes).
- Digest pins are ``sha256:`` over type-tagged canonical bodies
  (bool != int), so identical declarations replay to identical pins.

Fail-closed edges:

- Unknown image ids raise ``UnknownImageError`` (never fabricated).
- Duplicate image ids raise ``DuplicateImageError`` (never recycled).
- Bad modes, unknown formats/placeholders, same-format conversion,
  quality-on-lossless, non-int/bool dimensions, and non-increasing
  caller seqs are refused.
- A failed mutation still consumes its seq (fail-closed ledger
  position, batch-21 ``rbac_engine`` discipline).

Honest scope:

- This module books *declared* properties and *decisions*. It cannot
  verify that the pixels behind ``img-1`` are really 800x600 PNG, and
  an ``OptimizationRecord`` proves the decision was booked correctly,
  never that bytes were recompressed or shrunk. ``estimated`` savings
  figures are deliberately absent -- the module refuses to invent
  numbers it cannot measure. Pair with a real codec (libvips, Pillow)
  and a real edge worker for production I/O.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple

IMAGE_OPTIMIZATION_VERSION = "image-optimization.v1"
SCHEMA_PIN = "northstar.image-optimization.v1"

#: Pinned container vocabulary (shared by register/format targets).
FORMATS = ("png", "jpeg", "webp", "gif", "bmp", "tiff", "avif")

#: Containers where a quality setting is meaningful.
LOSSY_FORMATS = ("jpeg", "webp", "avif")

#: Cloudflare Polish optimization modes.
OPTIMIZE_MODES = ("lossless", "lossy")

#: Mirage lazy-load placeholder shapes.
PLACEHOLDERS = ("blur", "color", "none")

#: Default lossy quality when the caller does not pin one.
DEFAULT_QUALITY = 85

_MIN_DIM = 1
_MAX_DIM = 16384
_MIN_QUALITY = 1
_MAX_QUALITY = 100

_OPTIMIZATION_AUDIT_KINDS = (
    "registered",
    "optimized",
    "converted",
    "lazy-marked",
    "rejected",
)


class ImageOptimizationError(ValueError):
    """Base fail-closed error for image optimization."""


class UnknownImageError(ImageOptimizationError):
    """The image id is not in the registry."""


class DuplicateImageError(ImageOptimizationError):
    """The image id is already registered."""


class BadDimensionError(ImageOptimizationError):
    """A width/height is not an int in [1, 16384]."""


class UnknownFormatError(ImageOptimizationError):
    """The format is not in the pinned vocabulary."""


class UnknownModeError(ImageOptimizationError):
    """The optimize mode is not in the pinned vocabulary."""


class UnknownPlaceholderError(ImageOptimizationError):
    """The lazy placeholder is not in the pinned vocabulary."""


class BadQualityError(ImageOptimizationError):
    """Quality is missing, out of range, or disallowed for the mode."""


class SeqOrderError(ImageOptimizationError):
    """The caller seq did not strictly increase."""


def _check_seq_value(seq: int) -> None:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SeqOrderError("seq must be a positive int")


def _encode_tagged(value: object) -> bytes:
    """Type-tagged encoding so bool != int and NaN/inf never sneak in."""
    if isinstance(value, bool):
        return b"b" + (b"1" if value else b"0")
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise ImageOptimizationError("int outside safe range")
        return b"i" + str(value).encode("ascii")
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"s" + str(len(raw)).encode("ascii") + b":" + raw
    if value is None:
        return b"n"
    if isinstance(value, (tuple, list)):
        parts = b",".join(_encode_tagged(v) for v in value)
        return b"l" + str(len(value)).encode("ascii") + b":[" + parts + b"]"
    raise ImageOptimizationError(f"unencodable value type: {type(value)!r}")


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    h = hashlib.sha256()
    for name, value in parts:
        h.update(_encode_tagged(name))
        h.update(b"=")
        h.update(_encode_tagged(value))
        h.update(b";")
    return "sha256:" + h.hexdigest()


def _check_dimensions(width: int, height: int) -> None:
    for name, dim in (("width", width), ("height", height)):
        if isinstance(dim, bool) or not isinstance(dim, int):
            raise BadDimensionError(f"{name} must be an int, got {type(dim).__name__}")
        if not (_MIN_DIM <= dim <= _MAX_DIM):
            raise BadDimensionError(f"{name} out of range [{_MIN_DIM}, {_MAX_DIM}]")


def _check_format(fmt: str) -> None:
    if fmt not in FORMATS:
        raise UnknownFormatError(f"unknown format: {fmt!r}")


def _check_quality(quality: Optional[int], mode: str) -> int:
    """Validate quality against the optimize mode; return the effective one."""
    if mode == "lossless":
        if quality is not None:
            raise BadQualityError("quality is meaningless for lossless mode")
        return 0
    # lossy
    q = DEFAULT_QUALITY if quality is None else quality
    if isinstance(q, bool) or not isinstance(q, int):
        raise BadQualityError("quality must be an int")
    if not (_MIN_QUALITY <= q <= _MAX_QUALITY):
        raise BadQualityError(f"quality out of range [{_MIN_QUALITY}, {_MAX_QUALITY}]")
    return q


@dataclass(frozen=True)
class ImageRecord:
    image_id: str
    width: int
    height: int
    format: str
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class OptimizationRecord:
    opt_id: str
    image_id: str
    mode: str
    quality: int
    strip_metadata: bool
    from_width: int
    from_height: int
    to_width: int
    to_height: int
    resized: bool
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "opt_id": self.opt_id,
            "image_id": self.image_id,
            "mode": self.mode,
            "quality": self.quality,
            "strip_metadata": self.strip_metadata,
            "from_width": self.from_width,
            "from_height": self.from_height,
            "to_width": self.to_width,
            "to_height": self.to_height,
            "resized": self.resized,
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class FormatRecord:
    conv_id: str
    image_id: str
    from_format: str
    to_format: str
    quality: Optional[int]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "conv_id": self.conv_id,
            "image_id": self.image_id,
            "from_format": self.from_format,
            "to_format": self.to_format,
            "quality": self.quality,
            "seq": self.seq,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class LazyRecord:
    lazy_id: str
    image_id: str
    placeholder: str
    intrinsic_width: int
    intrinsic_height: int
    eager_above_fold: bool
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "lazy_id": self.lazy_id,
            "image_id": self.image_id,
            "placeholder": self.placeholder,
            "intrinsic_width": self.intrinsic_width,
            "intrinsic_height": self.intrinsic_height,
            "eager_above_fold": self.eager_above_fold,
            "seq": self.seq,
            "pin": self.pin,
        }


class ImageOptimization:
    """Deterministic registry of image-optimization decisions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: Dict[str, ImageRecord] = {}
        self._opts: Dict[str, OptimizationRecord] = {}
        self._convs: Dict[str, FormatRecord] = {}
        self._lazys: Dict[str, LazyRecord] = {}
        self._opt_counter = 0
        self._conv_counter = 0
        self._lazy_counter = 0
        self._last_seq = 0
        self._audit_log: list = []

    # -- seq discipline ------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        _check_seq_value(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq

    def _audit(self, kind: str, seq: int, detail: str = "") -> None:
        self._audit_log.append(
            image_optimization_audit_event(kind, seq, detail=detail)
        )

    def _require_image(self, image_id: str) -> ImageRecord:
        rec = self._images.get(image_id)
        if rec is None:
            raise UnknownImageError(f"unknown image id: {image_id!r}")
        return rec

    # -- registry -------------------------------------------------------

    def register(
        self,
        image_id: str,
        width: int,
        height: int,
        format: str,
        seq: int,
        *,
        source_digest: str = "",
    ) -> ImageRecord:
        """Pin a declared image's properties."""
        with self._lock:
            self._check_seq(seq)
            try:
                if not isinstance(image_id, str) or not image_id:
                    raise ImageOptimizationError("image_id must be a non-empty str")
                if image_id in self._images:
                    raise DuplicateImageError(f"duplicate image id: {image_id!r}")
                _check_dimensions(width, height)
                _check_format(format)
                if not isinstance(source_digest, str):
                    raise ImageOptimizationError("source_digest must be str")
                pin = _digest_tagged(
                    (
                        ("image_id", image_id),
                        ("width", width),
                        ("height", height),
                        ("format", format),
                        ("source_digest", source_digest),
                    )
                )
                rec = ImageRecord(
                    image_id=image_id,
                    width=width,
                    height=height,
                    format=format,
                    seq=seq,
                    pin=pin,
                )
                self._images[image_id] = rec
                self._audit("registered", seq, image_id)
                return rec
            except ImageOptimizationError:
                self._audit("rejected", seq, image_id if isinstance(image_id, str) else "")
                raise

    # -- optimize -------------------------------------------------------

    @staticmethod
    def _fit(
        width: int, height: int, max_width: Optional[int], max_height: Optional[int]
    ) -> Tuple[int, int]:
        """Aspect-fit (width, height) into optional bounds; never upscale."""
        target_w, target_h = width, height
        if max_width is not None:
            _check_dimensions(max_width, max_width)
            if target_w > max_width:
                scale = max_width / target_w
                target_w = max_width
                target_h = max(1, int(height * scale))
        if max_height is not None:
            _check_dimensions(max_height, max_height)
            if target_h > max_height:
                scale = max_height / target_h
                target_h = max_height
                target_w = max(1, int(target_w * scale))
        # never upscale: clamp back to source
        target_w = min(target_w, width)
        target_h = min(target_h, height)
        return target_w, target_h

    def optimize(
        self,
        image_id: str,
        seq: int,
        *,
        mode: str = "lossy",
        quality: Optional[int] = None,
        max_width: Optional[int] = None,
        max_height: Optional[int] = None,
        strip_metadata: bool = True,
    ) -> OptimizationRecord:
        """Book a Polish-style optimization decision for a registered image."""
        with self._lock:
            self._check_seq(seq)
            try:
                src = self._require_image(image_id)
                if mode not in OPTIMIZE_MODES:
                    raise UnknownModeError(f"unknown mode: {mode!r}")
                q = _check_quality(quality, mode)
                if not isinstance(strip_metadata, bool):
                    raise ImageOptimizationError("strip_metadata must be bool")
                if max_width is not None and not isinstance(max_width, int):
                    raise BadDimensionError("max_width must be int or None")
                if max_height is not None and not isinstance(max_height, int):
                    raise BadDimensionError("max_height must be int or None")
                to_w, to_h = self._fit(src.width, src.height, max_width, max_height)
                self._opt_counter += 1
                opt_id = f"opt-{self._opt_counter}"
                pin = _digest_tagged(
                    (
                        ("opt_id", opt_id),
                        ("image_id", image_id),
                        ("mode", mode),
                        ("quality", q),
                        ("strip_metadata", strip_metadata),
                        ("from_width", src.width),
                        ("from_height", src.height),
                        ("to_width", to_w),
                        ("to_height", to_h),
                        ("src_pin", src.pin),
                    )
                )
                rec = OptimizationRecord(
                    opt_id=opt_id,
                    image_id=image_id,
                    mode=mode,
                    quality=q,
                    strip_metadata=strip_metadata,
                    from_width=src.width,
                    from_height=src.height,
                    to_width=to_w,
                    to_height=to_h,
                    resized=(to_w, to_h) != (src.width, src.height),
                    seq=seq,
                    pin=pin,
                )
                self._opts[opt_id] = rec
                self._audit("optimized", seq, opt_id)
                return rec
            except ImageOptimizationError:
                self._audit("rejected", seq, image_id if isinstance(image_id, str) else "")
                raise

    # -- format ---------------------------------------------------------

    def format(
        self,
        image_id: str,
        target_format: str,
        seq: int,
        *,
        quality: Optional[int] = None,
    ) -> FormatRecord:
        """Book a container conversion for a registered image."""
        with self._lock:
            self._check_seq(seq)
            try:
                src = self._require_image(image_id)
                _check_format(target_format)
                if target_format == src.format:
                    raise ImageOptimizationError(
                        f"no-op conversion to the image's own format: {target_format!r}"
                    )
                if target_format in LOSSY_FORMATS:
                    q = DEFAULT_QUALITY if quality is None else quality
                    if isinstance(q, bool) or not isinstance(q, int):
                        raise BadQualityError("quality must be an int")
                    if not (_MIN_QUALITY <= q <= _MAX_QUALITY):
                        raise BadQualityError(
                            f"quality out of range [{_MIN_QUALITY}, {_MAX_QUALITY}]"
                        )
                else:
                    if quality is not None:
                        raise BadQualityError(
                            f"quality is meaningless for lossless target {target_format!r}"
                        )
                    q = None
                self._conv_counter += 1
                conv_id = f"conv-{self._conv_counter}"
                pin = _digest_tagged(
                    (
                        ("conv_id", conv_id),
                        ("image_id", image_id),
                        ("from_format", src.format),
                        ("to_format", target_format),
                        ("quality", q),
                        ("src_pin", src.pin),
                    )
                )
                rec = FormatRecord(
                    conv_id=conv_id,
                    image_id=image_id,
                    from_format=src.format,
                    to_format=target_format,
                    quality=q,
                    seq=seq,
                    pin=pin,
                )
                self._convs[conv_id] = rec
                self._audit("converted", seq, conv_id)
                return rec
            except ImageOptimizationError:
                self._audit("rejected", seq, image_id if isinstance(image_id, str) else "")
                raise

    # -- lazy -----------------------------------------------------------

    def lazy(
        self,
        image_id: str,
        seq: int,
        *,
        placeholder: str = "blur",
        eager_above_fold: bool = False,
    ) -> LazyRecord:
        """Book a Mirage-style lazy-load directive for a registered image."""
        with self._lock:
            self._check_seq(seq)
            try:
                src = self._require_image(image_id)
                if placeholder not in PLACEHOLDERS:
                    raise UnknownPlaceholderError(
                        f"unknown placeholder: {placeholder!r}"
                    )
                if not isinstance(eager_above_fold, bool):
                    raise ImageOptimizationError("eager_above_fold must be bool")
                self._lazy_counter += 1
                lazy_id = f"lazy-{self._lazy_counter}"
                pin = _digest_tagged(
                    (
                        ("lazy_id", lazy_id),
                        ("image_id", image_id),
                        ("placeholder", placeholder),
                        ("intrinsic_width", src.width),
                        ("intrinsic_height", src.height),
                        ("eager_above_fold", eager_above_fold),
                        ("src_pin", src.pin),
                    )
                )
                rec = LazyRecord(
                    lazy_id=lazy_id,
                    image_id=image_id,
                    placeholder=placeholder,
                    intrinsic_width=src.width,
                    intrinsic_height=src.height,
                    eager_above_fold=eager_above_fold,
                    seq=seq,
                    pin=pin,
                )
                self._lazys[lazy_id] = rec
                self._audit("lazy-marked", seq, lazy_id)
                return rec
            except ImageOptimizationError:
                self._audit("rejected", seq, image_id if isinstance(image_id, str) else "")
                raise

    # -- views ----------------------------------------------------------

    def image(self, image_id: str) -> ImageRecord:
        with self._lock:
            return self._require_image(image_id)

    def image_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._images))

    def optimization(self, opt_id: str) -> OptimizationRecord:
        with self._lock:
            rec = self._opts.get(opt_id)
            if rec is None:
                raise ImageOptimizationError(f"unknown optimization id: {opt_id!r}")
            return rec

    def conversion(self, conv_id: str) -> FormatRecord:
        with self._lock:
            rec = self._convs.get(conv_id)
            if rec is None:
                raise ImageOptimizationError(f"unknown conversion id: {conv_id!r}")
            return rec

    def lazy_record(self, lazy_id: str) -> LazyRecord:
        with self._lock:
            rec = self._lazys.get(lazy_id)
            if rec is None:
                raise ImageOptimizationError(f"unknown lazy id: {lazy_id!r}")
            return rec

    def audit_log(self) -> Tuple[Mapping[str, object], ...]:
        with self._lock:
            return tuple(self._audit_log)


def image_optimization_audit_event(
    kind: str,
    seq: int,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for image-optimization activity.

    Carries ids, digests, and dimensions only -- never pixel bytes.
    """
    if kind not in _OPTIMIZATION_AUDIT_KINDS:
        raise ImageOptimizationError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise ImageOptimizationError("seq must be a positive int")
    if not isinstance(detail, str):
        raise ImageOptimizationError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": IMAGE_OPTIMIZATION_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    o = ImageOptimization()
    rec = o.register("img-1", 800, 600, "png", 1)
    assert rec.pin.startswith("sha256:")
    opt = o.optimize("img-1", 2, mode="lossy", max_width=400)
    assert (opt.to_width, opt.to_height) == (400, 300) and opt.resized
    assert opt.quality == DEFAULT_QUALITY
    conv = o.format("img-1", "webp", 3, quality=80)
    assert conv.quality == 80
    lz = o.lazy("img-1", 4, placeholder="blur")
    assert (lz.intrinsic_width, lz.intrinsic_height) == (800, 600)
    evt = image_optimization_audit_event("optimized", 1)
    assert evt["schema"] == SCHEMA_PIN
    print("image-optimization OK: register, optimize, format, lazy, audit")


if __name__ == "__main__":
    main()
