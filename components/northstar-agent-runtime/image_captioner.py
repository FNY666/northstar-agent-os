"""BLIP-style image captioning, in-memory.

Research note: an *image captioner* (BLIP is the reference, Li et al.)
maps an image to natural-language text -- a caption, a set of semantic
tags, or a fuller description. The load-bearing production concerns, all
kept here:

* **Template discipline** -- because this module never runs a vision
  model, captions are deterministic templates over *host-registered*
  image metadata (scene, objects, tags, colors, dimensions). Identical
  registered metadata always yields the byte-identical caption; the
  generation is a pure function, never a hallucination with RNG.
* **Digest pins** -- every record carries a ``sha256:`` pin over its
  canonical body; a tampered caption or tag list no longer verifies.
  The pin proves the output came from the pinned input, never that the
  input truthfully describes the pixels.
* **Fail-closed registry** -- duplicate image ids, unknown image ids on
  caption/tags/describe, unknown styles, and bad metadata shapes are
  refused; no path invents content for an unregistered image.
* **Strict seqs** -- every mutation takes a caller-supplied strictly
  increasing int seq; the module never touches the wall clock.

Honest scope: this is a *caption bookkeeping* interface over a tiny
simulated generator, not a vision model. It cannot see pixels, cannot
verify that registered metadata matches any real image, and must not be
used where caption truth matters. Real deployments run BLIP (or a
successor) over the image bytes, register the bytes' digest here, and
record the model's own provenance.

Version pin: image-captioner.v1
Schema pin: northstar.image-captioner.v1
"""

from __future__ import annotations

import ast
import hashlib
import re
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
IMAGE_CAPTIONER_VERSION = "image-captioner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.image-captioner.v1"

#: Largest accepted metadata string in UTF-8 bytes.
MAX_TEXT_BYTES = 1 << 16

#: Caption styles this module implements (simulated subset).
_STYLES: FrozenSet[str] = frozenset({"alt", "neutral", "detailed"})

#: Tag id pattern: lowercase word tokens.
_TAG_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class ImageCaptionerError(Exception):
    """Base error for image captioning misuse or constraint violations."""


class UnknownImageError(ImageCaptionerError):
    """A caption/tags/describe named an image this module never registered."""


class DuplicateImageError(ImageCaptionerError):
    """An image id was registered twice (ids are never recycled)."""


class UnknownStyleError(ImageCaptionerError):
    """A caption requested a style this module does not implement."""


class ValidationError(ImageCaptionerError):
    """A field failed fail-closed validation."""


class SeqOrderError(ImageCaptionerError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_image_id(image_id: Any) -> str:
    if not isinstance(image_id, str) or not image_id.strip():
        raise ValidationError("image_id must be a non-empty str")
    if len(image_id.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValidationError("image_id too long")
    return image_id.strip()


def _check_dim(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an int, not bool/float")
    if value <= 0:
        raise ValidationError(f"{name} must be positive")
    return value


def _check_text(value: Any, name: str, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a str")
    text = value.strip()
    if required and not text:
        raise ValidationError(f"{name} must be non-empty")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValidationError(f"{name} too long")
    return text


def _check_tags(tags: Any) -> Tuple[str, ...]:
    if not isinstance(tags, (list, tuple)):
        raise ValidationError("tags must be a list/tuple of str")
    seen: List[str] = []
    for t in tags:
        if not isinstance(t, str):
            raise ValidationError("each tag must be a str")
        tag = t.strip().lower()
        if not _TAG_RE.match(tag):
            raise ValidationError(f"bad tag: {t!r}")
        if tag not in seen:
            seen.append(tag)
    if not seen:
        raise ValidationError("tags must be non-empty")
    return tuple(seen)


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _pseudo_confidence(image_id: str, tag: str) -> float:
    """Deterministic pseudo-confidence in [0, 1], derived from the pin chain.

    This is *not* a model score -- it is a stable ordering key pinned to
    (image_id, tag), so tag reports replay deterministically.
    """
    digest = hashlib.sha256(f"{image_id}\x00{tag}".encode("utf-8")).digest()
    return (int.from_bytes(digest[:4], "big") % 10000) / 10000.0


@dataclass(frozen=True)
class ImageRecord:
    """Registered image metadata (the caption source of truth)."""

    image_id: str
    width: int
    height: int
    scene: str
    objects: Tuple[str, ...]
    tags: Tuple[str, ...]
    colors: Tuple[str, ...]
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "scene": self.scene,
            "objects": list(self.objects),
            "tags": list(self.tags),
            "colors": list(self.colors),
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        body = {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "scene": self.scene,
            "objects": list(self.objects),
            "tags": list(self.tags),
            "colors": list(self.colors),
        }
        return _pin(body) == self.digest


@dataclass(frozen=True)
class CaptionRecord:
    """A deterministic caption generated for a registered image."""

    image_id: str
    style: str
    text: str
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "style": self.style,
            "text": self.text,
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        return _pin(
            {"image_id": self.image_id, "style": self.style, "text": self.text}
        ) == self.digest


@dataclass(frozen=True)
class TagScore:
    """One tag with its deterministic pseudo-confidence."""

    tag: str
    confidence: float


@dataclass(frozen=True)
class TagReport:
    """Semantic tags for an image, ordered by confidence desc."""

    image_id: str
    tags: Tuple[TagScore, ...]
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "tags": [
                {"tag": t.tag, "confidence": t.confidence} for t in self.tags
            ],
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        return _pin(
            {
                "image_id": self.image_id,
                "tags": [
                    {"tag": t.tag, "confidence": t.confidence}
                    for t in self.tags
                ],
            }
        ) == self.digest


@dataclass(frozen=True)
class DescriptionRecord:
    """A fuller description combining all registered metadata."""

    image_id: str
    text: str
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "text": self.text,
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        return _pin({"image_id": self.image_id, "text": self.text}) == self.digest


class ImageCaptioner:
    """Deterministic caption/tag/description bookkeeping for images.

    House style: frozen dataclasses, caller-supplied strictly increasing
    int seqs, RLock-guarded, fail-closed, stdlib-only, ``sha256:`` pins.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: Dict[str, ImageRecord] = {}
        self._last_seq = -1
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -----------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _lookup(self, image_id: str) -> ImageRecord:
        try:
            return self._images[image_id]
        except KeyError:
            raise UnknownImageError(f"unknown image: {image_id!r}")

    # -- registration -------------------------------------------------------

    def register_image(
        self,
        image_id: str,
        seq: int,
        *,
        width: int = 1,
        height: int = 1,
        scene: str = "unknown",
        objects: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        colors: Optional[List[str]] = None,
    ) -> ImageRecord:
        """Register an image's metadata; captions are derived from this.

        ``objects`` and ``colors`` are free-text lists; ``tags`` must be
        lowercase word tokens. Duplicate ids are refused fail-closed.
        """
        seq = self._claim_seq(seq)
        image_id = _check_image_id(image_id)
        width = _check_dim(width, "width")
        height = _check_dim(height, "height")
        scene = _check_text(scene, "scene")
        objects = tuple(
            _check_text(o, "object") for o in (objects or [])
        )
        tags = _check_tags(["untagged"] if tags is None else tags)
        colors = tuple(_check_text(c, "color") for c in (colors or []))
        with self._lock:
            if image_id in self._images:
                raise DuplicateImageError(
                    f"image already registered: {image_id!r}"
                )
            digest = _pin(
                {
                    "image_id": image_id,
                    "width": width,
                    "height": height,
                    "scene": scene,
                    "objects": list(objects),
                    "tags": list(tags),
                    "colors": list(colors),
                }
            )
            rec = ImageRecord(
                image_id=image_id,
                width=width,
                height=height,
                scene=scene,
                objects=objects,
                tags=tags,
                colors=colors,
                digest=digest,
                seq=seq,
            )
            self._images[image_id] = rec
            self._audit.append(
                image_captioner_audit_event("registered", seq, image_id)
            )
            return rec

    # -- captioning ---------------------------------------------------------

    @staticmethod
    def _render_caption(rec: ImageRecord, style: str) -> str:
        objects = ", ".join(rec.objects) if rec.objects else "no distinct objects"
        colors = ", ".join(rec.colors) if rec.colors else "unlisted colors"
        if style == "alt":
            return (
                f"Image of {rec.scene}"
                + (f" showing {objects}." if rec.objects else ".")
            )
        if style == "neutral":
            return (
                f"A photo of {rec.scene} with {objects}. "
                f"Dominant colors: {colors}."
            )
        # detailed
        dims = f"{rec.width}x{rec.height}"
        tags = ", ".join(rec.tags)
        return (
            f"A {dims} image depicting {rec.scene}. "
            f"Visible: {objects}. "
            f"Tags: {tags}. Dominant colors: {colors}."
        )

    def caption(
        self, image_id: str, seq: int, *, style: str = "neutral"
    ) -> CaptionRecord:
        """Generate a deterministic caption for a registered image.

        Styles: ``alt`` (accessibility one-liner), ``neutral`` (BLIP-style
        short caption), ``detailed`` (metadata-rich caption).
        """
        seq = self._claim_seq(seq)
        image_id = _check_image_id(image_id)
        if not isinstance(style, str) or style not in _STYLES:
            raise UnknownStyleError(f"unknown caption style: {style!r}")
        with self._lock:
            rec = self._lookup(image_id)
            text = self._render_caption(rec, style)
            digest = _pin(
                {"image_id": image_id, "style": style, "text": text}
            )
            out = CaptionRecord(
                image_id=image_id, style=style, text=text, digest=digest,
                seq=seq,
            )
            self._audit.append(
                image_captioner_audit_event("captioned", seq, image_id)
            )
            return out

    def tags(
        self, image_id: str, seq: int, *, max_tags: int = 10
    ) -> TagReport:
        """Return semantic tags for an image, ordered by confidence desc.

        Confidence is a deterministic ordering key pinned to (image_id,
        tag) -- not a model score.
        """
        seq = self._claim_seq(seq)
        image_id = _check_image_id(image_id)
        if isinstance(max_tags, bool) or not isinstance(max_tags, int):
            raise ValidationError("max_tags must be an int")
        if max_tags <= 0:
            raise ValidationError("max_tags must be positive")
        with self._lock:
            rec = self._lookup(image_id)
            scored = [
                TagScore(tag=t, confidence=_pseudo_confidence(image_id, t))
                for t in rec.tags
            ]
            scored.sort(key=lambda s: (-s.confidence, s.tag))
            top = tuple(scored[:max_tags])
            digest = _pin(
                {
                    "image_id": image_id,
                    "tags": [
                        {"tag": s.tag, "confidence": s.confidence}
                        for s in top
                    ],
                }
            )
            out = TagReport(
                image_id=image_id, tags=top, digest=digest, seq=seq
            )
            self._audit.append(
                image_captioner_audit_event("tagged", seq, image_id)
            )
            return out

    def describe(self, image_id: str, seq: int) -> DescriptionRecord:
        """Return a fuller description combining all registered metadata."""
        seq = self._claim_seq(seq)
        image_id = _check_image_id(image_id)
        with self._lock:
            rec = self._lookup(image_id)
            detailed = self._render_caption(rec, "detailed")
            text = (
                f"This is a description of image {image_id}. {detailed} "
                f"Registered scene label: {rec.scene}."
            )
            digest = _pin({"image_id": image_id, "text": text})
            out = DescriptionRecord(
                image_id=image_id, text=text, digest=digest, seq=seq
            )
            self._audit.append(
                image_captioner_audit_event("described", seq, image_id)
            )
            return out

    # -- views ---------------------------------------------------------------

    def image(self, image_id: str) -> ImageRecord:
        with self._lock:
            return self._lookup(_check_image_id(image_id))

    def image_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._images))

    def image_count(self) -> int:
        with self._lock:
            return len(self._images)

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def image_captioner_audit_event(
    kind: str, seq: int, image_id: str
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for this module (ids + pins only)."""
    if kind not in ("registered", "captioned", "tagged", "described", "rejected"):
        raise ValidationError(f"unknown audit kind: {kind}")
    _check_seq(seq)
    return {
        "kind": kind,
        "seq": seq,
        "image_id": image_id,
        "module": "image-captioner",
        "version": IMAGE_CAPTIONER_VERSION,
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    ic = ImageCaptioner()
    rec = ic.register_image(
        "img-1", 1, width=640, height=480, scene="a beach at sunset",
        objects=["sun", "waves"], tags=["beach", "sunset"], colors=["orange"],
    )
    assert rec.verify()
    cap = ic.caption("img-1", 2, style="alt")
    assert "beach at sunset" in cap.text and cap.verify()
    tag = ic.tags("img-1", 3)
    assert tag.tags and tag.verify()
    desc = ic.describe("img-1", 4)
    assert "beach at sunset" in desc.text and desc.verify()
    print("image-captioner OK: register, caption, tags, describe, pins")


if __name__ == "__main__":
    main()
