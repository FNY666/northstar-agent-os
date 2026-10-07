"""Tesseract-style optical character recognition bookkeeping.

A deterministic, single-host state machine over the OCR pipeline shape
(Tesseract lineage):

- ``submit(image_id, width, height, seq)`` -> frozen ``ImageRecord``:
  register the image canvas (the pixel grid the model "saw").
- ``recognize(image_id, words, seq)`` -> frozen ``RecognitionResult``:
  book the host-reported word hypotheses - each word carries ``text``,
  ``confidence`` in [0, 1], and a pixel ``bbox``. Geometry is
  validated fail-closed (boxes inside the image, well-formed), the
  word stream is digest-pinned, and aggregate confidence is computed.
- ``layout(image_id, seq)`` -> frozen ``LayoutReport``: deterministic
  layout analysis over the latest recognition - baseline bands from
  vertical word overlap, column segments from x-gaps, paragraphs from
  inter-line gaps or horizontal misalignment, blocks from horizontal
  alignment. Thresholds are derived from the data (medians), never
  caller-tuned, so replays converge.
- ``confidence(image_id, seq, threshold=...)`` -> frozen
  ``ConfidenceReport``: mean/min/max confidence plus the words below
  the caller threshold (review candidates).

Simulation boundary (honest scope): this module does not look at
pixels. There is no model, no image decoder, no feature extractor.
``recognize()`` pins what the *host claims the model reported* - a
lying host gets a consistent ledger of lies (GIGO). What the module
does prove is structural: geometry is sane, confidence values are
finite and bounded, the layout hierarchy is derived deterministically
from the reported words, and every record is digest-pinned so later
tampering is detectable. Pair with an attested model + a pinned
image digest (see ``doc_scanner``) for a production claim.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock), RLock-guarded, fail-closed error taxonomy,
stdlib-only, ``sha256:`` digest pins over type-tagged canonical
encodings (bool is not int; NaN/inf and |n| >= 2**53 refused),
``audit.ndjson/1`` records, ``main()`` self-check.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
OCR_ENGINE_VERSION = "ocr-engine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ocr-engine.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Hard cap on image dimensions (guardrail against absurd canvases).
MAX_DIMENSION = 100_000

#: Hard cap on words per recognition call (guardrail).
MAX_WORDS = 100_000

#: Hard cap on word text length (guardrail).
MAX_TEXT_LEN = 256


class OCRError(Exception):
    """Base fail-closed OCR error."""


class InvalidImageError(OCRError):
    """Bad image id, dimensions, or dpi."""


class DuplicateImageError(OCRError):
    """image_id already registered (ids are never recycled)."""


class UnknownImageError(OCRError):
    """image_id was never submitted."""


class InvalidWordError(OCRError):
    """Bad word text, confidence, or bbox geometry."""


class NoRecognitionError(OCRError):
    """layout()/confidence() called before any recognize()."""


class SeqOrderError(OCRError):
    """Caller seq did not strictly increase (mutating calls)."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _check_seq(seq: int, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise OCRError("%s must be a non-negative int, got %r" % (what, seq))
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidImageError("%s must be a non-empty str" % what)
    return value


def _check_dimension(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidImageError("%s must be an int, got %r" % (what, value))
    if not (1 <= value <= MAX_DIMENSION):
        raise InvalidImageError(
            "%s must be in [1, %d], got %r" % (what, MAX_DIMENSION, value)
        )
    return value


def _check_confidence(value: Any, what: str = "confidence") -> float:
    if isinstance(value, bool):
        raise InvalidWordError("%s must be a number in [0, 1], got bool" % what)
    if isinstance(value, int):
        if value not in (0, 1):
            raise InvalidWordError(
                "%s must be in [0, 1], got %r" % (what, value)
            )
        return float(value)
    if not isinstance(value, float) or not math.isfinite(value):
        raise InvalidWordError("%s must be a finite number, got %r" % (what, value))
    if not (0.0 <= value <= 1.0):
        raise InvalidWordError("%s must be in [0, 1], got %r" % (what, value))
    return value


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


@dataclass(frozen=True)
class ImageRecord:
    """Frozen canvas registration: the pixel grid the model "saw"."""

    image_id: str
    width: int
    height: int
    dpi: Optional[int]
    seq: int
    digest: str
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "width": self.width,
            "height": self.height,
            "dpi": self.dpi,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class WordRecord:
    """Frozen word hypothesis: text + confidence + pixel bbox."""

    word_id: str
    text: str
    confidence: float
    bbox: Tuple[int, int, int, int]
    digest: str
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "word_id": self.word_id,
            "text": self.text,
            "confidence": self.confidence,
            "bbox": list(self.bbox),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RecognitionResult:
    """Frozen recognition ledger entry: the validated word stream."""

    recognition_id: str
    image_id: str
    words: Tuple[WordRecord, ...]
    word_count: int
    mean_confidence: float
    digest: str
    seq: int
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "recognition_id": self.recognition_id,
            "image_id": self.image_id,
            "words": [w.as_dict() for w in self.words],
            "word_count": self.word_count,
            "mean_confidence": self.mean_confidence,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LineRecord:
    """Frozen text line: x-ordered words sharing a baseline band."""

    line_id: str
    word_ids: Tuple[str, ...]
    text: str
    bbox: Tuple[int, int, int, int]
    mean_confidence: float
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "line_id": self.line_id,
            "word_ids": list(self.word_ids),
            "text": self.text,
            "bbox": list(self.bbox),
            "mean_confidence": self.mean_confidence,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ParagraphRecord:
    """Frozen paragraph: consecutive lines with small inter-line gaps."""

    paragraph_id: str
    line_ids: Tuple[str, ...]
    text: str
    bbox: Tuple[int, int, int, int]
    mean_confidence: float
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "paragraph_id": self.paragraph_id,
            "line_ids": list(self.line_ids),
            "text": self.text,
            "bbox": list(self.bbox),
            "mean_confidence": self.mean_confidence,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class BlockRecord:
    """Frozen layout block: paragraphs in one column run."""

    block_id: str
    paragraph_ids: Tuple[str, ...]
    bbox: Tuple[int, int, int, int]
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "block_id": self.block_id,
            "paragraph_ids": list(self.paragraph_ids),
            "bbox": list(self.bbox),
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LayoutReport:
    """Frozen layout analysis over the latest recognition."""

    image_id: str
    recognition_id: str
    lines: Tuple[LineRecord, ...]
    paragraphs: Tuple[ParagraphRecord, ...]
    blocks: Tuple[BlockRecord, ...]
    digest: str
    seq: int
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "recognition_id": self.recognition_id,
            "lines": [ln.as_dict() for ln in self.lines],
            "paragraphs": [p.as_dict() for p in self.paragraphs],
            "blocks": [b.as_dict() for b in self.blocks],
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LowConfidenceWord:
    """A word below the review threshold."""

    word_id: str
    text: str
    confidence: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "word_id": self.word_id,
            "text": self.text,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ConfidenceReport:
    """Frozen confidence aggregate over the latest recognition."""

    image_id: str
    recognition_id: str
    word_count: int
    mean_confidence: float
    min_confidence: float
    max_confidence: float
    threshold: float
    low_confidence: Tuple[LowConfidenceWord, ...]
    digest: str
    seq: int
    version: str = OCR_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "image_id": self.image_id,
            "recognition_id": self.recognition_id,
            "word_count": self.word_count,
            "mean_confidence": self.mean_confidence,
            "min_confidence": self.min_confidence,
            "max_confidence": self.max_confidence,
            "threshold": self.threshold,
            "low_confidence": [w.as_dict() for w in self.low_confidence],
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


class OCREngine:
    """Tesseract-shaped OCR bookkeeping: submit / recognize / layout / confidence."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._images: Dict[str, ImageRecord] = {}
        self._recognitions: Dict[str, List[RecognitionResult]] = {}
        self._counter = 0

    # -- seq discipline --------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        """Mutating calls claim strictly-increasing seqs.

        The claim happens before any other validation, so a failed
        mutation consumes its seq (fail-closed ledger position).
        """
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                "seq %d did not exceed last claimed seq %d" % (seq, self._last_seq)
            )
        self._last_seq = seq
        return seq

    # -- image registry --------------------------------------------------

    def submit(
        self,
        image_id: str,
        width: int,
        height: int,
        seq: int,
        *,
        dpi: Optional[int] = None,
    ) -> ImageRecord:
        """Register an image canvas; duplicate ids refused fail-closed."""
        with self._lock:
            seq = self._claim_seq(seq)
            image_id = _check_id(image_id, "image_id")
            width = _check_dimension(width, "width")
            height = _check_dimension(height, "height")
            if dpi is not None:
                if isinstance(dpi, bool) or not isinstance(dpi, int) or dpi <= 0:
                    raise InvalidImageError("dpi must be a positive int or None")
            if image_id in self._images:
                raise DuplicateImageError("image_id %r already registered" % image_id)
            body = {
                "image_id": image_id,
                "width": width,
                "height": height,
                "dpi": dpi,
                "seq": seq,
            }
            record = ImageRecord(
                image_id=image_id,
                width=width,
                height=height,
                dpi=dpi,
                seq=seq,
                digest=_digest(jcs_canonical_json(body)),
            )
            self._images[image_id] = record
            self._recognitions[image_id] = []
            return record

    def image(self, image_id: str) -> ImageRecord:
        with self._lock:
            try:
                return self._images[image_id]
            except KeyError:
                raise UnknownImageError("unknown image_id %r" % (image_id,)) from None

    def image_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._images))

    # -- recognition -----------------------------------------------------

    def _validate_word(
        self, raw: Any, index: int, width: int, height: int
    ) -> Tuple[str, float, Tuple[int, int, int, int]]:
        if not isinstance(raw, Mapping):
            raise InvalidWordError("word %d must be a mapping, got %r" % (index, raw))
        missing = {"text", "confidence", "bbox"} - set(raw.keys())
        if missing:
            raise InvalidWordError(
                "word %d missing keys: %s" % (index, sorted(missing))
            )
        text = raw["text"]
        if not isinstance(text, str) or not text:
            raise InvalidWordError("word %d text must be a non-empty str" % index)
        if len(text) > MAX_TEXT_LEN:
            raise InvalidWordError(
                "word %d text exceeds %d chars" % (index, MAX_TEXT_LEN)
            )
        confidence = _check_confidence(raw["confidence"], "word %d confidence" % index)
        bbox = raw["bbox"]
        if (
            not isinstance(bbox, (list, tuple))
            or len(bbox) != 4
            or any(isinstance(c, bool) or not isinstance(c, int) for c in bbox)
        ):
            raise InvalidWordError(
                "word %d bbox must be 4 ints [x0, y0, x1, y1]" % index
            )
        x0, y0, x1, y1 = (int(c) for c in bbox)
        if not (x0 < x1 and y0 < y1):
            raise InvalidWordError(
                "word %d bbox must satisfy x0<x1 and y0<y1, got %r" % (index, bbox)
            )
        if not (0 <= x0 and x1 <= width and 0 <= y0 and y1 <= height):
            raise InvalidWordError(
                "word %d bbox %r outside image %dx%d" % (index, bbox, width, height)
            )
        return text, confidence, (x0, y0, x1, y1)

    def recognize(
        self,
        image_id: str,
        words: Sequence[Mapping[str, Any]],
        seq: int,
    ) -> RecognitionResult:
        """Book host-reported word hypotheses for an image.

        Validates every word fail-closed (text, finite confidence in
        [0, 1], bbox inside the image), pins the stream with a digest,
        and aggregates mean confidence.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            image = self.image(image_id)
            if (
                not isinstance(words, (list, tuple))
                or isinstance(words, (str, bytes))
                or len(words) == 0
            ):
                raise InvalidWordError("words must be a non-empty list of mappings")
            if len(words) > MAX_WORDS:
                raise InvalidWordError(
                    "words exceeds guardrail %d" % MAX_WORDS
                )
            validated = [
                self._validate_word(raw, i, image.width, image.height)
                for i, raw in enumerate(words)
            ]
            self._counter += 1
            recognition_id = "rc-%d" % self._counter
            word_records: List[WordRecord] = []
            for i, (text, confidence, bbox) in enumerate(validated):
                wbody = {
                    "recognition_id": recognition_id,
                    "word_id": "w-%d" % (i + 1),
                    "text": text,
                    "confidence": confidence,
                    "bbox": list(bbox),
                }
                word_records.append(
                    WordRecord(
                        word_id="w-%d" % (i + 1),
                        text=text,
                        confidence=confidence,
                        bbox=bbox,
                        digest=_digest(jcs_canonical_json(wbody)),
                    )
                )
            mean_conf = sum(w.confidence for w in word_records) / len(word_records)
            digest = _digest(
                jcs_canonical_json(
                    {
                        "recognition_id": recognition_id,
                        "image_id": image_id,
                        "words": [w.as_dict() for w in word_records],
                        "seq": seq,
                    }
                )
            )
            result = RecognitionResult(
                recognition_id=recognition_id,
                image_id=image_id,
                words=tuple(word_records),
                word_count=len(word_records),
                mean_confidence=mean_conf,
                digest=digest,
                seq=seq,
            )
            self._recognitions[image_id].append(result)
            return result

    def recognition(self, image_id: str) -> RecognitionResult:
        """Latest recognition for an image (raises if none)."""
        with self._lock:
            self.image(image_id)
            history = self._recognitions[image_id]
            if not history:
                raise NoRecognitionError(
                    "no recognition for image_id %r yet" % image_id
                )
            return history[-1]

    def recognitions(self, image_id: str) -> Tuple[RecognitionResult, ...]:
        with self._lock:
            self.image(image_id)
            return tuple(self._recognitions[image_id])

    # -- layout ----------------------------------------------------------

    @staticmethod
    def _bbox_union(boxes: Sequence[Tuple[int, int, int, int]]) -> Tuple[int, int, int, int]:
        return (
            min(b[0] for b in boxes),
            min(b[1] for b in boxes),
            max(b[2] for b in boxes),
            max(b[3] for b in boxes),
        )

    def _group_lines(self, words: Sequence[WordRecord]) -> List[List[WordRecord]]:
        """Group words into lines: baseline bands, then column segments.

        Words join a baseline band by vertical overlap (>40% of the
        smaller height). Within a band, an x-gap wider than twice the
        median word width starts a new segment, so two-column text
        yields one line per column. Deterministic throughout.
        """
        ordered = sorted(words, key=lambda w: ((w.bbox[1] + w.bbox[3]) / 2.0, w.bbox[0]))
        bands: List[List[WordRecord]] = []
        for word in ordered:
            placed = False
            wh = word.bbox[3] - word.bbox[1]
            for band in bands:
                lbox = self._bbox_union([w.bbox for w in band])
                ly0, ly1 = lbox[1], lbox[3]
                lh = ly1 - ly0
                overlap = min(word.bbox[3], ly1) - max(word.bbox[1], ly0)
                if overlap > 0.4 * min(wh, lh):
                    band.append(word)
                    placed = True
                    break
            if not placed:
                bands.append([word])
        seg_gap = 2.0 * _median([w.bbox[2] - w.bbox[0] for w in words])
        lines: List[List[WordRecord]] = []
        for band in bands:
            band.sort(key=lambda w: w.bbox[0])
            current = [band[0]]
            for w in band[1:]:
                if w.bbox[0] - current[-1].bbox[2] > seg_gap:
                    lines.append(current)
                    current = [w]
                else:
                    current.append(w)
            lines.append(current)
        lines.sort(key=lambda ln: self._bbox_union([w.bbox for w in ln])[1])
        return lines

    @staticmethod
    def _h_overlap(
        a: Tuple[int, int, int, int], b: Tuple[int, int, int, int]
    ) -> int:
        return max(0, min(a[2], b[2]) - max(a[0], b[0]))

    def layout(self, image_id: str, seq: int) -> LayoutReport:
        """Derive the block/paragraph/line hierarchy deterministically.

        Pure view over the latest recognition: baseline bands from
        vertical word overlap, bands split into column segments by
        x-gap (>2x median word width), segments into paragraphs by
        inter-line gap (>1.5x median line height) or horizontal
        misalignment (<50% overlap of the narrower width), paragraphs
        into blocks by horizontal alignment (>=50% overlap joins the
        first matching block, so a text column stays one block).
        All thresholds are data-derived medians - replays converge.
        """
        with self._lock:
            seq = _check_seq(seq)
            result = self.recognition(image_id)
            words = list(result.words)

            line_groups = self._group_lines(words)
            line_records: List[LineRecord] = []
            for i, group in enumerate(line_groups):
                box = self._bbox_union([w.bbox for w in group])
                mean_c = sum(w.confidence for w in group) / len(group)
                line_records.append(
                    LineRecord(
                        line_id="l-%d" % (i + 1),
                        word_ids=tuple(w.word_id for w in group),
                        text=" ".join(w.text for w in group),
                        bbox=box,
                        mean_confidence=mean_c,
                    )
                )

            line_heights = [ln.bbox[3] - ln.bbox[1] for ln in line_records]
            med_lh = _median(line_heights)

            # Lines -> paragraphs: a new paragraph starts when the
            # inter-line gap is large (>1.5x median line height) or the
            # line does not horizontally align with the paragraph
            # (overlap < 50% of the narrower width).
            paragraphs: List[List[LineRecord]] = []
            for ln in line_records:
                if paragraphs:
                    prev_box = self._bbox_union([l.bbox for l in paragraphs[-1]])
                    gap = ln.bbox[1] - prev_box[3]
                    narrower = min(
                        prev_box[2] - prev_box[0], ln.bbox[2] - ln.bbox[0]
                    )
                    aligned = narrower <= 0 or self._h_overlap(
                        prev_box, ln.bbox
                    ) >= 0.5 * narrower
                    if gap > 1.5 * med_lh or not aligned:
                        paragraphs.append([ln])
                        continue
                if not paragraphs:
                    paragraphs.append([ln])
                else:
                    paragraphs[-1].append(ln)

            para_records: List[ParagraphRecord] = []
            for i, grp in enumerate(paragraphs):
                box = self._bbox_union([ln.bbox for ln in grp])
                mean_c = sum(ln.mean_confidence for ln in grp) / len(grp)
                para_records.append(
                    ParagraphRecord(
                        paragraph_id="p-%d" % (i + 1),
                        line_ids=tuple(ln.line_id for ln in grp),
                        text="\n".join(ln.text for ln in grp),
                        bbox=box,
                        mean_confidence=mean_c,
                    )
                )

            # Paragraphs -> blocks: a paragraph joins the first block
            # whose bbox it horizontally overlaps (>= 50% of the
            # narrower width); otherwise it opens a new block. This
            # keeps vertically stacked, x-aligned paragraphs (a text
            # column) in one block while column breaks split.
            blocks: List[List[ParagraphRecord]] = []
            for para in para_records:
                joined = False
                for grp in blocks:
                    gbox = self._bbox_union([p.bbox for p in grp])
                    narrower = min(
                        gbox[2] - gbox[0], para.bbox[2] - para.bbox[0]
                    )
                    if narrower > 0 and self._h_overlap(
                        gbox, para.bbox
                    ) >= 0.5 * narrower:
                        grp.append(para)
                        joined = True
                        break
                if not joined:
                    blocks.append([para])

            block_records = [
                BlockRecord(
                    block_id="b-%d" % (i + 1),
                    paragraph_ids=tuple(p.paragraph_id for p in grp),
                    bbox=self._bbox_union([p.bbox for p in grp]),
                )
                for i, grp in enumerate(blocks)
            ]

            digest = _digest(
                jcs_canonical_json(
                    {
                        "image_id": image_id,
                        "recognition_id": result.recognition_id,
                        "lines": [ln.as_dict() for ln in line_records],
                        "paragraphs": [p.as_dict() for p in para_records],
                        "blocks": [b.as_dict() for b in block_records],
                    }
                )
            )
            return LayoutReport(
                image_id=image_id,
                recognition_id=result.recognition_id,
                lines=tuple(line_records),
                paragraphs=tuple(para_records),
                blocks=tuple(block_records),
                digest=digest,
                seq=seq,
            )

    # -- confidence --------------------------------------------------------

    def confidence(
        self, image_id: str, seq: int, *, threshold: float = 0.8
    ) -> ConfidenceReport:
        """Aggregate confidence over the latest recognition.

        Words strictly below ``threshold`` are listed as review
        candidates, in recognition order.
        """
        with self._lock:
            seq = _check_seq(seq)
            threshold = _check_confidence(threshold, "threshold")
            result = self.recognition(image_id)
            confs = [w.confidence for w in result.words]
            low = tuple(
                LowConfidenceWord(word_id=w.word_id, text=w.text, confidence=w.confidence)
                for w in result.words
                if w.confidence < threshold
            )
            digest = _digest(
                jcs_canonical_json(
                    {
                        "image_id": image_id,
                        "recognition_id": result.recognition_id,
                        "threshold": threshold,
                        "low": [w.as_dict() for w in low],
                    }
                )
            )
            return ConfidenceReport(
                image_id=image_id,
                recognition_id=result.recognition_id,
                word_count=result.word_count,
                mean_confidence=sum(confs) / len(confs),
                min_confidence=min(confs),
                max_confidence=max(confs),
                threshold=threshold,
                low_confidence=low,
                digest=digest,
                seq=seq,
            )


_AUDIT_KINDS = (
    "image-submitted",
    "recognized",
    "layout-built",
    "confidence-computed",
    "rejected",
)


def ocr_engine_audit_event(
    kind: str,
    seq: int,
    detail: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shape an audit.ndjson/1 record for OCR operations (ids + pins only)."""
    if kind not in _AUDIT_KINDS:
        raise OCRError("unknown audit kind: %r" % kind)
    seq = _check_seq(seq)
    record: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": "ocr-engine",
        "module_version": OCR_ENGINE_VERSION,
        "kind": kind,
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise OCRError("detail must be a mapping")
        record["detail"] = dict(detail)
    return record


def main() -> None:
    engine = OCREngine()
    engine.submit("img-1", 800, 600, seq=1)
    result = engine.recognize(
        "img-1",
        [
            {"text": "hello", "confidence": 0.95, "bbox": [10, 10, 60, 30]},
            {"text": "world", "confidence": 0.90, "bbox": [70, 12, 120, 32]},
            {"text": "foo", "confidence": 0.50, "bbox": [10, 60, 50, 80]},
            {"text": "bar", "confidence": 0.85, "bbox": [60, 62, 100, 82]},
        ],
        seq=2,
    )
    assert result.word_count == 4
    assert abs(result.mean_confidence - 0.8) < 1e-9
    report = engine.layout("img-1", seq=3)
    assert len(report.lines) == 2, report.lines
    assert [ln.text for ln in report.lines] == ["hello world", "foo bar"]
    assert len(report.paragraphs) == 1
    assert len(report.blocks) == 1
    conf = engine.confidence("img-1", seq=4)
    assert conf.word_count == 4
    assert conf.min_confidence == 0.5 and conf.max_confidence == 0.95
    assert [w.text for w in conf.low_confidence] == ["foo"]
    try:
        engine.recognize(
            "img-1",
            [{"text": "bad", "confidence": 1.5, "bbox": [0, 0, 10, 10]}],
            seq=5,
        )
    except InvalidWordError:
        pass
    else:
        raise AssertionError("bad confidence not refused")
    print("ocr-engine OK: submit, recognize, layout, confidence, refusals")
