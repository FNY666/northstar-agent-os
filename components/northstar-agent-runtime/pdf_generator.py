"""PDF document generator: page/text object model with a real serializer.

Research note: a PDF file (ISO 32000) is a *serialized object graph*:
a header (``%PDF-1.7``), indirect objects (catalog, pages, page,
content streams, fonts), a cross-reference table with byte offsets,
and a trailer pointing at the catalog. The load-bearing production
concerns, all kept here:

* **Byte-exact xref** -- object offsets are computed from the actual
  serialized bytes, so the xref table is genuinely consistent
  (test-verified by re-reading every offset).
* **Fail-closed strings** -- PDF literal strings ``(...)`` only carry
  escaped printable ASCII; backslash and parens are escaped, and any
  non-printable/non-ASCII character is refused. The module has no
  font-encoding machinery, so it does not pretend to emit Unicode.
* **Deterministic layout** -- objects are numbered catalog-first,
  fonts sorted by name, text lines emitted at explicit coordinates
  (PDF-native origin: bottom-left, y up, 72 points per inch).
* **Save locks the document** -- after ``save()`` any further edit
  raises ``FinalizedError`` fail-closed. A published document must
  not change under a reader's eyes.

Honest scope: this is a document *object model plus a serializer*
for PDF-shaped bytes, stdlib-only and simulated. It emits no
compressed streams, embeds no fonts, and cannot prove a real PDF
renderer accepts or renders the bytes. Strings are host-reported --
the module pins structure, not truth.

Version pin: pdf-generator.v1
Schema pin: northstar.pdf-generator.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
PDF_GENERATOR_VERSION = "pdf-generator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.pdf-generator.v1"

#: PDF header line.
PDF_HEADER = "%PDF-1.7"

#: PDF tail marker.
PDF_EOF = "%%EOF"

#: Pinned Type1 base fonts the serializer can reference.
_BASE_FONTS = (
    "Courier",
    "Courier-Bold",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Times-Bold",
    "Times-Roman",
)

#: Default page size in points: US Letter.
_DEFAULT_WIDTH = 612
_DEFAULT_HEIGHT = 792

#: Points per inch.
_PTS_PER_INCH = 72

#: Audit kinds shaped for ``audit.ndjson/1``.
_AUDIT_KINDS = (
    "document-created",
    "page-added",
    "text-added",
    "document-saved",
    "rejected",
)


class PDFError(Exception):
    """Base error for PDF generator misuse or constraint violations."""


class DuplicateDocumentError(PDFError):
    """A document id was registered twice."""


class UnknownDocumentError(PDFError):
    """An operation named a document id that does not exist."""


class UnknownPageError(PDFError):
    """An operation named a page number that does not exist."""


class FinalizedError(PDFError):
    """A document was mutated after ``save()``."""


class ValidationError(PDFError):
    """A field failed fail-closed validation."""


class SeqOrderError(PDFError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must be a non-empty str")
    return value.strip()


def _check_dim(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{what} must be an int, not bool")
    if value <= 0:
        raise ValidationError(f"{what} must be positive")
    return value


def _check_coord(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{what} must be an int, not bool")
    return value


def _check_size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("font size must be an int, not bool")
    if not 1 <= value <= 288:
        raise ValidationError("font size must be in [1, 288] points")
    return value


def _check_font(value: Any) -> str:
    if not isinstance(value, str) or value not in _BASE_FONTS:
        raise ValidationError(
            f"font must be one of {', '.join(_BASE_FONTS)}, got {value!r}"
        )
    return value


def _check_pdf_string(value: Any, what: str) -> str:
    """Fail-closed PDF literal-string content: printable ASCII only."""
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{what} must be a non-empty str")
    for ch in value:
        if not (0x20 <= ord(ch) <= 0x7E) and ch not in ("\n", "\t"):
            raise ValidationError(
                f"{what} must be printable ASCII (no font encoding simulated)"
            )
    return value


def _escape_pdf_string(value: str) -> str:
    """Escape a validated string for a PDF literal ``(...)``."""
    out = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return out.replace("\n", "\\n").replace("\t", "\\t")


def _pin(body: Any) -> str:
    digest = hashlib.sha256(jcs_canonical_json(body)).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class PageRecord:
    """A page registered on a document (PDF-native bottom-left origin)."""

    doc_id: str
    page_no: int
    width: int
    height: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "page_no": self.page_no,
            "width": self.width,
            "height": self.height,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class TextRecord:
    """A text element placed on a page; coordinates in points."""

    doc_id: str
    page_no: int
    text_id: str
    x: int
    y: int
    text: str
    font: str
    size: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "page_no": self.page_no,
            "text_id": self.text_id,
            "x": self.x,
            "y": self.y,
            "text": self.text,
            "font": self.font,
            "size": self.size,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class PDFDocument:
    """The serialized document: PDF-shaped bytes plus pins."""

    doc_id: str
    body: bytes
    page_count: int
    object_count: int
    byte_length: int
    pin: str
    model_pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "page_count": self.page_count,
            "object_count": self.object_count,
            "byte_length": self.byte_length,
            "pin": self.pin,
            "model_pin": self.model_pin,
        }


@dataclass
class _DocState:
    doc_id: str
    title: Optional[str]
    author: Optional[str]
    subject: Optional[str]
    keywords: Optional[str]
    pages: List[PageRecord] = field(default_factory=list)
    texts: List[TextRecord] = field(default_factory=list)
    saved: bool = False
    text_counter: int = 0


class PDFGenerator:
    """PDF object model + byte-exact serializer, deterministic."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._docs: Dict[str, _DocState] = {}
        self._last_seq: int = -1

    # -- seq -----------------------------------------------------------
    def _take_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _require_unfinalized(self, doc: _DocState) -> None:
        if doc.saved:
            raise FinalizedError(f"document {doc.doc_id!r} is already saved")

    def _require_doc(self, doc_id: str) -> _DocState:
        doc = self._docs.get(doc_id)
        if doc is None:
            raise UnknownDocumentError(f"unknown document {doc_id!r}")
        return doc

    # -- document -------------------------------------------------------
    def new_document(
        self,
        doc_id: str,
        seq: int,
        title: Optional[str] = None,
        author: Optional[str] = None,
        subject: Optional[str] = None,
        keywords: Optional[str] = None,
    ) -> str:
        """Register a new document; returns the document id."""
        with self._lock:
            self._take_seq(seq)
            doc_id = _check_id(doc_id, "doc_id")
            if doc_id in self._docs:
                raise DuplicateDocumentError(f"document {doc_id!r} already exists")
            meta = {
                "title": title,
                "author": author,
                "subject": subject,
                "keywords": keywords,
            }
            for key, value in meta.items():
                if value is not None:
                    _check_pdf_string(value, key)
            self._docs[doc_id] = _DocState(
                doc_id=doc_id,
                title=title,
                author=author,
                subject=subject,
                keywords=keywords,
            )
            return doc_id

    # -- pages -----------------------------------------------------------
    def page(
        self,
        doc_id: str,
        seq: int,
        width: int = _DEFAULT_WIDTH,
        height: int = _DEFAULT_HEIGHT,
    ) -> PageRecord:
        """Append a page; returns the frozen page record."""
        with self._lock:
            self._take_seq(seq)
            doc_id = _check_id(doc_id, "doc_id")
            doc = self._require_doc(doc_id)
            self._require_unfinalized(doc)
            width = _check_dim(width, "width")
            height = _check_dim(height, "height")
            page_no = len(doc.pages) + 1
            record = PageRecord(
                doc_id=doc_id,
                page_no=page_no,
                width=width,
                height=height,
                pin=_pin([doc_id, page_no, width, height]),
            )
            doc.pages.append(record)
            return record

    # -- text ------------------------------------------------------------
    def text(
        self,
        doc_id: str,
        page_no: int,
        seq: int,
        x: int,
        y: int,
        text: str,
        font: str = "Helvetica",
        size: int = 12,
    ) -> TextRecord:
        """Place text on a page; returns the frozen text record."""
        with self._lock:
            self._take_seq(seq)
            doc_id = _check_id(doc_id, "doc_id")
            doc = self._require_doc(doc_id)
            self._require_unfinalized(doc)
            if isinstance(page_no, bool) or not isinstance(page_no, int):
                raise ValidationError("page_no must be an int, not bool")
            if not 1 <= page_no <= len(doc.pages):
                raise UnknownPageError(
                    f"document {doc_id!r} has {len(doc.pages)} page(s), "
                    f"no page {page_no}"
                )
            x = _check_coord(x, "x")
            y = _check_coord(y, "y")
            text = _check_pdf_string(text, "text")
            font = _check_font(font)
            size = _check_size(size)
            doc.text_counter += 1
            text_id = f"tx-{doc.text_counter}"
            record = TextRecord(
                doc_id=doc_id,
                page_no=page_no,
                text_id=text_id,
                x=x,
                y=y,
                text=text,
                font=font,
                size=size,
                pin=_pin([doc_id, page_no, text_id, x, y, text, font, size]),
            )
            doc.texts.append(record)
            return record

    # -- views ------------------------------------------------------------
    def documents(self) -> List[str]:
        with self._lock:
            return sorted(self._docs)

    def pages(self, doc_id: str) -> List[PageRecord]:
        with self._lock:
            return list(self._require_doc(_check_id(doc_id, "doc_id")).pages)

    def texts(self, doc_id: str, page_no: Optional[int] = None) -> List[TextRecord]:
        with self._lock:
            doc = self._require_doc(_check_id(doc_id, "doc_id"))
            if page_no is None:
                return list(doc.texts)
            if isinstance(page_no, bool) or not isinstance(page_no, int):
                raise ValidationError("page_no must be an int, not bool")
            return [t for t in doc.texts if t.page_no == page_no]

    def is_saved(self, doc_id: str) -> bool:
        with self._lock:
            return self._require_doc(_check_id(doc_id, "doc_id")).saved

    # -- serialization -----------------------------------------------------
    def save(self, doc_id: str, seq: int) -> PDFDocument:
        """Serialize the document to PDF-shaped bytes; locks the document."""
        with self._lock:
            self._take_seq(seq)
            doc_id = _check_id(doc_id, "doc_id")
            doc = self._require_doc(doc_id)
            self._require_unfinalized(doc)
            if not doc.pages:
                raise ValidationError("cannot save a document with no pages")
            body = self._serialize(doc)
            model_pin = _pin(
                [
                    doc_id,
                    [p.as_dict() for p in doc.pages],
                    [t.as_dict() for t in doc.texts],
                ]
            )
            record = PDFDocument(
                doc_id=doc_id,
                body=body,
                page_count=len(doc.pages),
                object_count=self._object_count(doc),
                byte_length=len(body),
                pin="sha256:" + hashlib.sha256(body).hexdigest(),
                model_pin=model_pin,
            )
            doc.saved = True
            return record

    # -- serializer internals -----------------------------------------------
    def _object_count(self, doc: _DocState) -> int:
        """1 catalog + 1 pages + 2 per page + 1 per font + optional info."""
        n = 2 + 2 * len(doc.pages) + len(self._fonts_used(doc))
        if self._info_fields(doc):
            n += 1
        return n

    @staticmethod
    def _fonts_used(doc: _DocState) -> List[str]:
        return sorted({t.font for t in doc.texts})

    @staticmethod
    def _info_fields(doc: _DocState) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if doc.title is not None:
            info["Title"] = doc.title
        if doc.author is not None:
            info["Author"] = doc.author
        if doc.subject is not None:
            info["Subject"] = doc.subject
        if doc.keywords is not None:
            info["Keywords"] = doc.keywords
        return info

    def _serialize(self, doc: _DocState) -> bytes:
        n_pages = len(doc.pages)
        fonts = self._fonts_used(doc)
        # Pages with no text still reference a font in /Resources; the
        # fallback font must have an object, or the page dangles.
        if any(
            not any(t.page_no == p.page_no for t in doc.texts)
            for p in doc.pages
        ):
            fonts = sorted(set(fonts) | {"Helvetica"})
        # Object ids: 1 catalog, 2 pages tree, pages 3..3+P-1,
        # contents 3+P..3+2P-1, fonts after, optional info last.
        page_ids = [3 + i for i in range(n_pages)]
        content_ids = [3 + n_pages + i for i in range(n_pages)]
        font_ids = {f: 3 + 2 * n_pages + j for j, f in enumerate(fonts)}
        info_fields = self._info_fields(doc)
        info_id = 3 + 2 * n_pages + len(fonts) if info_fields else None

        objects: Dict[int, bytes] = {}

        # 1: catalog
        objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
        # 2: page tree
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[2] = (
            f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>"
        ).encode("ascii")

        # pages + contents
        for i, page in enumerate(doc.pages):
            per_page_fonts = sorted(
                {t.font for t in doc.texts if t.page_no == page.page_no}
            ) or ["Helvetica"]
            font_refs = " ".join(
                f"/F{k + 1} {font_ids[f]} 0 R"
                for k, f in enumerate(per_page_fonts)
            )
            objects[page_ids[i]] = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {page.width} {page.height}] "
                f"/Contents {content_ids[i]} 0 R "
                f"/Resources << /Font << {font_refs} >> >> >>"
            ).encode("ascii")
            objects[content_ids[i]] = self._content_stream(doc, page, per_page_fonts)

        # fonts
        for font_name, fid in font_ids.items():
            objects[fid] = (
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{font_name} >>"
            ).encode("ascii")

        # info
        if info_id is not None:
            entries = " ".join(
                f"/{k} ({_escape_pdf_string(v)})" for k, v in info_fields.items()
            )
            objects[info_id] = f"<< {entries} >>".encode("ascii")

        # assemble with byte-exact xref
        out = bytearray()
        out += PDF_HEADER.encode("ascii") + b"\n"
        offsets: Dict[int, int] = {}
        max_id = max(objects)
        for obj_id in range(1, max_id + 1):
            offsets[obj_id] = len(out)
            out += f"{obj_id} 0 obj\n".encode("ascii")
            out += objects[obj_id] + b"\nendobj\n"
        xref_pos = len(out)
        out += f"xref\n0 {max_id + 1}\n".encode("ascii")
        out += b"0000000000 65535 f \n"
        for obj_id in range(1, max_id + 1):
            out += f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii")
        trailer = f"<< /Size {max_id + 1} /Root 1 0 R"
        if info_id is not None:
            trailer += f" /Info {info_id} 0 R"
        trailer += " >>"
        out += f"trailer\n{trailer}\nstartxref\n{xref_pos}\n{PDF_EOF}\n".encode(
            "ascii"
        )
        return bytes(out)

    @staticmethod
    def _content_stream(
        doc: _DocState, page: PageRecord, per_page_fonts: List[str]
    ) -> bytes:
        """Build the page content stream object body."""
        lines: List[str] = []
        font_index = {f: k + 1 for k, f in enumerate(per_page_fonts)}
        for t in doc.texts:
            if t.page_no != page.page_no:
                continue
            ref = font_index[t.font]
            leading = int(round(t.size * 1.2)) or t.size
            for n, raw in enumerate(t.text.split("\n")):
                yy = t.y - n * leading
                lines.append(
                    f"BT /F{ref} {t.size} Tf {t.x} {yy} Td "
                    f"({_escape_pdf_string(raw)}) Tj ET"
                )
        data = "\n".join(lines).encode("ascii")
        return (
            f"<< /Length {len(data)} >>\nstream\n".encode("ascii")
            + data
            + b"\nendstream"
        )


def pdf_generator_audit_event(
    kind: str, seq: int, detail: Mapping[str, Any]
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module."""
    _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise ValidationError(f"unknown audit kind {kind!r}")
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
        "version": PDF_GENERATOR_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    gen = PDFGenerator()
    gen.new_document("DOC-1", 1, title="Hello", author="northstar")
    gen.page("DOC-1", 2)
    gen.text("DOC-1", 1, 3, 72, 700, "Hello, world!", font="Helvetica", size=24)
    gen.text("DOC-1", 1, 4, 72, 670, "line one\nline two", font="Courier", size=12)
    doc = gen.save("DOC-1", 5)
    assert doc.body.startswith(b"%PDF-1.7")
    assert doc.body.rstrip().endswith(b"%%EOF")
    assert doc.page_count == 1
    assert b"/BaseFont /Helvetica" in doc.body
    assert b"/BaseFont /Courier" in doc.body
    assert b"(Hello, world!)" in doc.body
    print("pdf-generator OK: document, pages, text, byte-exact save")


if __name__ == "__main__":
    main()
