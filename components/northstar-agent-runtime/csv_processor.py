"""CSV parse/emit/validate interface (RFC 4180 bookkeeping).

Research motivation: CSV remains the lingua franca of data exchange between
agents and legacy systems -- exports, reports, bulk imports. RFC 4180 is a
short spec, but real-world CSV breaks in a handful of predictable ways
(unbalanced quotes, ragged rows, mixed line endings, unescaped embedded
newlines), and a parser that *guesses* through them corrupts data silently.

This module pins the deterministic bookkeeping half of that shape:

- ``CSVProcessor`` -- owns the dialect (delimiter, quote char, line
  terminator; RFC 4180 defaults). ``parse()`` turns text into a frozen
  ``ParsedCSV`` (header row, data rows, per-row digests), ``emit()`` turns
  rows into a frozen ``EmittedCSV`` (CRLF text, minimal quoting),
  ``validate()`` returns a frozen ``ValidationReport`` describing every
  dialect violation without raising.
- ``csv_processor_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``parsed`` / ``emitted`` / ``validated`` / ``rejected``);
  caller-supplied seqs only.

RFC 4180 rules pinned here:

- Records are separated by CRLF (bare LF/CR are tolerated on parse and
  reported by ``validate()``; emit always writes CRLF).
- Fields containing the delimiter, a double-quote, or a line break are
  enclosed in double quotes; a literal double-quote inside a quoted field
  is escaped as ``""``.
- Every record must have the same number of fields; a header row is
  required (parse of empty text is a fail-closed error, not an empty
  table).
- Spaces are part of a field and are never trimmed or skipped.

Fail-closed edges (fail loudly, never guess):

- Unbalanced quotes (unterminated quoted field) raise
  ``UnbalancedQuoteError`` on ``parse()``; ``validate()`` reports it as
  data instead.
- Ragged rows (field count != header count) raise ``RaggedRowError`` on
  ``parse()``; ``validate()`` reports them as data instead.
- Inputs must be ``str``; non-str input, non-str fields on emit, and
  non-increasing caller seqs are refused.
- Digest pins are ``sha256:`` over type-tagged canonical bodies (bool !=
  int; NaN/inf refused), so identical content replays to identical pins.

Honest scope:

- This module books *reported* text. It cannot verify that a quoted field
  was meant to be quoted by the sender; ``parse()`` decodes what the
  bytes say, it does not recover authorial intent.
- Emitted text is a *canonical* rendering, not a byte-identical copy of
  any input that was parsed: parse/emit round-trips preserve the table,
  not the original quoting choices.
- Line-ending normalization is on the caller: ``parse()`` accepts LF,
  CRLF, and CR, but ``validate()`` always notes non-CRLF endings so the
  drift is visible.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Optional, Sequence, Tuple

CSV_PROCESSOR_VERSION = "csv-processor.v1"
SCHEMA_PIN = "northstar.csv-processor.v1"

_RFC4180_DELIMITER = ","
_RFC4180_QUOTECHAR = '"'
_RFC4180_LINETERMINATOR = "\r\n"


class CSVError(ValueError):
    """Base fail-closed error for the CSV processor."""


class UnbalancedQuoteError(CSVError):
    """A quoted field was never terminated."""


class RaggedRowError(CSVError):
    """A record did not carry the same field count as the header."""


class EmptyInputError(CSVError):
    """Nothing was given to parse or emit."""


class BadDialectError(CSVError):
    """The dialect configuration is invalid."""


class BadRecordError(CSVError):
    """A record failed structural validation."""


class SeqOrderError(CSVError):
    """Caller-supplied seq did not increase monotonically."""


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    """sha256 pin over type-tagged canonical encoding.

    bool != int, NaN/inf refused (same discipline as the batch line), so
    the pin binds content without float-serialization ambiguity.
    """
    import math

    buf = []
    for tag, value in parts:
        if isinstance(value, bool):
            body = "bool:" + ("1" if value else "0")
        elif isinstance(value, int):
            if abs(value) >= 2**53:
                raise CSVError("integer exceeds safe range for pinning")
            body = "int:" + str(value)
        elif isinstance(value, str):
            body = "str:" + value
        elif isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise CSVError("NaN/inf cannot be pinned")
            body = "float:" + repr(value)
        elif value is None:
            body = "none"
        else:
            raise CSVError(f"unpinable type for digest: {type(value).__name__}")
        buf.append(tag + "=" + body)
    return "sha256:" + hashlib.sha256("|".join(buf).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ParsedCSV:
    """A parsed CSV table: header plus data rows, digest-pinned."""

    header: Tuple[str, ...]
    rows: Tuple[Tuple[str, ...], ...]
    record_count: int
    field_count: int
    line_ending: str
    digest: str
    seq: int

    def as_dict(self):
        return {
            "header": list(self.header),
            "rows": [list(r) for r in self.rows],
            "record_count": self.record_count,
            "field_count": self.field_count,
            "line_ending": self.line_ending,
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class EmittedCSV:
    """Emitted CSV text: canonical CRLF rendering, digest-pinned."""

    text: str
    record_count: int
    field_count: int
    digest: str
    seq: int

    def as_dict(self):
        return {
            "text": self.text,
            "record_count": self.record_count,
            "field_count": self.field_count,
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ValidationReport:
    """Validation verdict for CSV text: valid plus per-issue findings."""

    valid: bool
    issues: Tuple[str, ...]
    record_count: int
    field_count: int
    line_ending: str
    digest: str
    seq: int

    def as_dict(self):
        return {
            "valid": self.valid,
            "issues": list(self.issues),
            "record_count": self.record_count,
            "field_count": self.field_count,
            "line_ending": self.line_ending,
            "digest": self.digest,
            "seq": self.seq,
        }


class CSVProcessor:
    """RFC 4180 CSV parse/emit/validate as deterministic bookkeeping.

    Dialect defaults to RFC 4180 (``,``, ``"``, CRLF). The dialect is
    pinned at construction; every mutating call takes a strictly
    increasing caller ``seq`` (no wall clock).
    """

    def __init__(
        self,
        delimiter: str = _RFC4180_DELIMITER,
        quotechar: str = _RFC4180_QUOTECHAR,
        lineterminator: str = _RFC4180_LINETERMINATOR,
    ) -> None:
        if not (isinstance(delimiter, str) and len(delimiter) == 1):
            raise BadDialectError("delimiter must be a single character")
        if not (isinstance(quotechar, str) and len(quotechar) == 1):
            raise BadDialectError("quotechar must be a single character")
        if delimiter == quotechar:
            raise BadDialectError("delimiter and quotechar must differ")
        if lineterminator not in ("\r\n", "\n", "\r"):
            raise BadDialectError("lineterminator must be CRLF, LF, or CR")
        self._delimiter = delimiter
        self._quotechar = quotechar
        self._lineterminator = lineterminator
        self._lock = threading.RLock()
        self._last_seq = 0

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._last_seq:
            raise SeqOrderError("seq must be strictly increasing")
        self._last_seq = seq

    def _split_records(self, text: str) -> Tuple[Tuple[str, ...], ...]:
        """Split text into records, respecting quoted embedded newlines.

        Returns a tuple of raw record strings (quotes preserved).
        Raises UnbalancedQuoteError if a quoted field never terminates.
        """
        qc = self._quotechar
        records: list[str] = []
        buf: list[str] = []
        in_quotes = False
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if in_quotes:
                if ch == qc:
                    if i + 1 < n and text[i + 1] == qc:
                        buf.append(qc)
                        buf.append(qc)
                        i += 2
                        continue
                    in_quotes = False
                    buf.append(ch)
                    i += 1
                    continue
                buf.append(ch)
                i += 1
                continue
            if ch == qc:
                in_quotes = True
                buf.append(ch)
                i += 1
                continue
            if ch == "\r":
                if i + 1 < n and text[i + 1] == "\n":
                    records.append("".join(buf))
                    buf = []
                    i += 2
                else:
                    records.append("".join(buf))
                    buf = []
                    i += 1
                continue
            if ch == "\n":
                records.append("".join(buf))
                buf = []
                i += 1
                continue
            buf.append(ch)
            i += 1
        if in_quotes:
            raise UnbalancedQuoteError("unterminated quoted field")
        tail = "".join(buf)
        if tail:
            records.append(tail)
        return tuple(records)

    def _split_fields(self, record: str) -> Tuple[str, ...]:
        """Split one raw record into fields, unescaping quotes."""
        qc = self._quotechar
        delim = self._delimiter
        fields: list[str] = []
        buf: list[str] = []
        in_quotes = False
        i = 0
        n = len(record)
        # A quoted field must start the field to be quoted; track position.
        at_field_start = True
        while i < n:
            ch = record[i]
            if in_quotes:
                if ch == qc:
                    if i + 1 < n and record[i + 1] == qc:
                        buf.append(qc)
                        i += 2
                        continue
                    in_quotes = False
                    i += 1
                    continue
                buf.append(ch)
                i += 1
                continue
            if ch == qc and at_field_start:
                in_quotes = True
                at_field_start = False
                i += 1
                continue
            if ch == delim:
                fields.append("".join(buf))
                buf = []
                at_field_start = True
                i += 1
                continue
            buf.append(ch)
            at_field_start = False
            i += 1
        if in_quotes:
            raise UnbalancedQuoteError("unterminated quoted field")
        fields.append("".join(buf))
        return tuple(fields)

    def _detect_line_ending(self, text: str) -> str:
        if "\r\n" in text:
            return "\r\n"
        if "\n" in text:
            return "\n"
        if "\r" in text:
            return "\r"
        return ""

    def _pin_table(
        self, header: Tuple[str, ...], rows: Tuple[Tuple[str, ...], ...]
    ) -> str:
        parts: list[Tuple[str, object]] = [("version", CSV_PROCESSOR_VERSION)]
        parts.append(("nfields", len(header)))
        for f in header:
            parts.append(("h", f))
        for row in rows:
            for f in row:
                parts.append(("c", f))
            parts.append(("r_end", len(row)))
        return _digest_tagged(tuple(parts))

    def parse(self, text: str, seq: int) -> ParsedCSV:
        """Parse CSV text into a frozen table.

        Fail-closed: empty input, unbalanced quotes, and ragged rows
        raise; bare LF/CR endings are accepted (recorded on the record).
        """
        with self._lock:
            self._check_seq(seq)
            if not isinstance(text, str):
                raise BadRecordError("parse input must be str")
            if text == "":
                raise EmptyInputError("nothing to parse")
            records = self._split_records(text)
            rows = tuple(self._split_fields(r) for r in records)
            header = rows[0]
            data = rows[1:]
            width = len(header)
            for idx, row in enumerate(data):
                if len(row) != width:
                    raise RaggedRowError(
                        f"row {idx + 1} has {len(row)} fields, header has {width}"
                    )
            line_ending = self._detect_line_ending(text)
            digest = self._pin_table(header, data)
            return ParsedCSV(
                header=header,
                rows=data,
                record_count=len(data),
                field_count=width,
                line_ending=line_ending,
                digest=digest,
                seq=seq,
            )

    def emit(
        self,
        header: Sequence[str],
        rows: Sequence[Sequence[str]],
        seq: int,
    ) -> EmittedCSV:
        """Emit a canonical CRLF rendering of the table.

        Fields containing the delimiter, the quote char, or any line
        break are quoted; embedded quotes are doubled. Spaces are never
        trimmed. Fail-closed on empty headers, ragged rows, and non-str
        fields.
        """
        with self._lock:
            self._check_seq(seq)
            header_t = tuple(header)
            if len(header_t) == 0:
                raise EmptyInputError("header must not be empty")
            for f in header_t:
                if not isinstance(f, str):
                    raise BadRecordError("header fields must be str")
            rows_t = tuple(tuple(r) for r in rows)
            for idx, row in enumerate(rows_t):
                for f in row:
                    if not isinstance(f, str):
                        raise BadRecordError(f"row {idx} field must be str")
                if len(row) != len(header_t):
                    raise RaggedRowError(
                        f"row {idx} has {len(row)} fields, header has {len(header_t)}"
                    )
            qc = self._quotechar
            delim = self._delimiter

            def render_field(value: str) -> str:
                if (
                    delim in value
                    or qc in value
                    or "\r" in value
                    or "\n" in value
                ):
                    return qc + value.replace(qc, qc + qc) + qc
                return value

            lines = [delim.join(render_field(f) for f in header_t)]
            for row in rows_t:
                lines.append(delim.join(render_field(f) for f in row))
            text = self._lineterminator.join(lines) + self._lineterminator
            digest = self._pin_table(header_t, rows_t)
            return EmittedCSV(
                text=text,
                record_count=len(rows_t),
                field_count=len(header_t),
                digest=digest,
                seq=seq,
            )

    def validate(self, text: str, seq: int) -> ValidationReport:
        """Validate CSV text without raising on content problems.

        Returns a report: valid plus one issue string per violation
        (unbalanced quotes, ragged rows, non-CRLF endings, empty input).
        Structural input-type errors (non-str) still raise.
        """
        with self._lock:
            self._check_seq(seq)
            if not isinstance(text, str):
                raise BadRecordError("validate input must be str")
            issues: list[str] = []
            record_count = 0
            field_count = 0
            line_ending = self._detect_line_ending(text)
            if text == "":
                issues.append("empty-input")
            else:
                try:
                    records = self._split_records(text)
                except UnbalancedQuoteError:
                    issues.append("unbalanced-quote")
                    records = ()
                rows: Tuple[Tuple[str, ...], ...] = ()
                if "unbalanced-quote" not in issues:
                    try:
                        rows = tuple(self._split_fields(r) for r in records)
                    except UnbalancedQuoteError:
                        issues.append("unbalanced-quote")
                if rows and "unbalanced-quote" not in issues:
                    field_count = len(rows[0])
                    for idx, row in enumerate(rows[1:]):
                        if len(row) != field_count:
                            issues.append(
                                f"ragged-row:{idx + 1}:{len(row)}!={field_count}"
                            )
                    record_count = len(rows) - 1
                if line_ending and line_ending != "\r\n":
                    issues.append(f"line-ending:{repr(line_ending)}")
            digest = _digest_tagged(
                (
                    ("version", CSV_PROCESSOR_VERSION),
                    ("text", text),
                    ("valid", len(issues) == 0),
                )
            )
            return ValidationReport(
                valid=len(issues) == 0,
                issues=tuple(issues),
                record_count=record_count,
                field_count=field_count,
                line_ending=line_ending,
                digest=digest,
                seq=seq,
            )


_CSV_AUDIT_KINDS = ("parsed", "emitted", "validated", "rejected")


def csv_processor_audit_event(
    kind: str,
    seq: int,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for CSV processor activity.

    Carries ids, digests, and the issue list only -- never raw CSV text.
    """
    if kind not in _CSV_AUDIT_KINDS:
        raise CSVError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise CSVError("seq must be a positive int")
    if not isinstance(detail, str):
        raise CSVError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": CSV_PROCESSOR_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    p = CSVProcessor()
    parsed = p.parse('a,b\r\n"x","y,y"\r\n', 1)
    assert parsed.record_count == 1 and parsed.header == ("a", "b")
    emitted = p.emit(["a", "b"], [["x", "y,y"]], 2)
    assert emitted.text == 'a,b\r\nx,"y,y"\r\n'
    report = p.validate("a,b\n1,2\n", 3)
    assert not report.valid and "line-ending:'\\n'" in report.issues
    good = p.validate("a,b\r\n1,2\r\n", 4)
    assert good.valid and good.issues == ()
    evt = csv_processor_audit_event("parsed", 1)
    assert evt["schema"] == SCHEMA_PIN
    print("csv-processor OK: parse, emit, validate, audit")


if __name__ == "__main__":
    main()
