"""Excel sheet/cell/formula content model and formula-evaluation contract, in-memory.

Research note: XLSX (Office Open XML) is a ZIP of XML parts -- workbooks,
worksheets, shared strings. The load-bearing production concerns, all kept
here:

* **Sheet/cell ledger** -- sheets own cells keyed by A1 refs; every cell is
  a frozen, ``sha256:``-pinned record.
* **A1 refs** -- parsed strictly: columns ``A``..``XFD`` (16,384, the
  Excel cap), rows 1..1,048,576. Anything else is refused fail-closed.
* **Value discipline** -- cell values are ``int`` | ``str`` | ``bool`` |
  ``None``; floats are refused outright (no IEEE contamination, no
  >2^53 JCS caveat), ints are bounded by +-2^53 to keep the canonical
  encoding lossless.
* **Formula contract** -- ``=SUM(A1:B3)`` / ``AVG`` / ``MIN`` / ``MAX`` /
  ``COUNT`` over same-sheet ranges only. A formula pins its expression and
  its referenced refs; ``evaluate()`` computes deterministically over the
  pinned cells. Blank (missing) cells count as 0, as in Excel; string cells
  inside a numeric range raise ``EvalError`` fail-closed; cross-sheet refs
  are refused.

Honest scope: this is the *content model and formula contract*, not an
XLSX engine. The module emits no ZIP/XML bytes, parses no XLSX, and
cannot prove a spreadsheet was produced or delivered -- ``formula()``
books the formula text, ``evaluate()`` evaluates the pinned cells. Pair
with a real XLSX parser (openpyxl, Sheets API) for production I/O.

Version pin: excel-handler.v1
Schema pin: northstar.excel-handler.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
EXCEL_HANDLER_VERSION = "excel-handler.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.excel-handler.v1"

#: Excel limits: columns A..XFD, rows 1..1,048,576.
MAX_COLS = 16384
MAX_ROWS = 1048576

#: Largest int the canonical encoding keeps lossless.
INT_BOUND = 2 ** 53

#: Pinned formula functions.
_FUNCTIONS = ("SUM", "AVG", "MIN", "MAX", "COUNT")

#: Audit kinds for audit.ndjson/1 records.
_AUDIT_KINDS = ("sheet-created", "cell-set", "formula-set", "evaluated", "rejected")

_REF_RE = re.compile(r"^([A-Z]{1,3})(\d{1,7})$")
_FORMULA_RE = re.compile(r"^=([A-Z]+)\(([A-Z]{1,3}\d{1,7})(?::([A-Z]{1,3}\d{1,7}))?\)$")


class ExcelError(Exception):
    """Base error for spreadsheet misuse or constraint violations."""


class UnknownSheetError(ExcelError):
    """An operation named a sheet id that does not exist."""


class DuplicateSheetError(ExcelError):
    """A sheet id or name was registered twice."""


class BadRefError(ExcelError):
    """An A1 ref failed strict validation."""


class FormulaError(ExcelError):
    """A formula expression failed strict validation."""


class EvalError(ExcelError):
    """A formula could not be evaluated over the pinned cells."""


class ValidationError(ExcelError):
    """A field failed fail-closed validation."""


class SeqOrderError(ExcelError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must be a non-empty str")
    return value.strip()


def _pin(body: Any) -> str:
    digest = hashlib.sha256(jcs_canonical_json(body)).hexdigest()
    return f"sha256:{digest}"


def _col_to_index(col: str) -> int:
    """``A`` -> 1 ... ``XFD`` -> 16384."""
    idx = 0
    for ch in col:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx


def parse_ref(ref: Any) -> Tuple[str, int, int]:
    """Parse an A1 ref -> (canonical ref, col index, row). Refuses junk."""
    if not isinstance(ref, str):
        raise BadRefError("ref must be a str")
    ref = ref.strip().upper()
    m = _REF_RE.match(ref)
    if not m:
        raise BadRefError(f"bad A1 ref {ref!r}")
    col_s, row_s = m.group(1), m.group(2)
    col = _col_to_index(col_s)
    row = int(row_s)
    if not 1 <= col <= MAX_COLS:
        raise BadRefError(f"column {col_s!r} out of A..XFD")
    if not 1 <= row <= MAX_ROWS:
        raise BadRefError(f"row {row} out of 1..1048576")
    return (f"{col_s}{row}", col, row)


def _index_to_col(idx: int) -> str:
    out = ""
    while idx:
        idx, rem = divmod(idx - 1, 26)
        out = chr(65 + rem) + out
    return out


def _check_value(value: Any, what: str) -> Any:
    if isinstance(value, float):
        raise ValidationError(f"{what}: floats refused (exact ints only)")
    if isinstance(value, bool):
        raise ValidationError(f"{what}: bools refused as cell values")
    if isinstance(value, int) and abs(value) >= INT_BOUND:
        raise ValidationError(f"{what}: int out of +-2^53")
    if not (value is None or isinstance(value, (int, str))):
        raise ValidationError(f"{what}: must be int | str | None")
    return value


def _parse_formula(expr: Any) -> Tuple[str, Tuple[int, int], Tuple[int, int]]:
    """Parse ``=FUNC(A1:B2)`` -> (func, (c1,r1), (c2,r2)) normalized."""
    if not isinstance(expr, str):
        raise FormulaError("formula must be a str")
    expr = expr.strip().upper()
    m = _FORMULA_RE.match(expr)
    if not m:
        raise FormulaError(f"bad formula shape {expr!r}")
    func, start_s, end_s = m.group(1), m.group(2), m.group(3) or m.group(2)
    if func not in _FUNCTIONS:
        raise FormulaError(f"unknown function {func!r}")
    try:
        _, c1, r1 = parse_ref(start_s)
        _, c2, r2 = parse_ref(end_s)
    except BadRefError as e:
        raise FormulaError(f"bad range ref: {e}")
    c_lo, c_hi = min(c1, c2), max(c1, c2)
    r_lo, r_hi = min(r1, r2), max(r1, r2)
    return (func, (c_lo, r_lo), (c_hi, r_hi))


@dataclass(frozen=True)
class SheetRecord:
    """A pinned sheet registration."""

    sheet_id: str
    name: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sheet_id": self.sheet_id,
            "name": self.name,
            "seq": self.seq,
            "digest": self.digest,
            "version": EXCEL_HANDLER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class CellRecord:
    """A pinned cell value."""

    sheet_id: str
    ref: str
    value: Any
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sheet_id": self.sheet_id,
            "ref": self.ref,
            "value": self.value,
            "seq": self.seq,
            "digest": self.digest,
            "version": EXCEL_HANDLER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class FormulaRecord:
    """A pinned formula: expression plus the refs it references."""

    sheet_id: str
    ref: str
    expression: str
    function: str
    range_refs: Tuple[str, ...]
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sheet_id": self.sheet_id,
            "ref": self.ref,
            "expression": self.expression,
            "function": self.function,
            "range_refs": list(self.range_refs),
            "seq": self.seq,
            "digest": self.digest,
            "version": EXCEL_HANDLER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class EvalResult:
    """The deterministic result of evaluating a formula over pinned cells."""

    sheet_id: str
    ref: str
    expression: str
    value: Any
    formula_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sheet_id": self.sheet_id,
            "ref": self.ref,
            "expression": self.expression,
            "value": self.value,
            "formula_digest": self.formula_digest,
            "seq": self.seq,
            "digest": self.digest,
            "version": EXCEL_HANDLER_VERSION,
            "schema": SCHEMA_PIN,
        }


class ExcelHandler:
    """Sheet/cell/formula bookkeeping, fail-closed and digest-pinned."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._sheets: Dict[str, SheetRecord] = {}
        self._names: Dict[str, str] = {}
        self._cells: Dict[Tuple[str, str], CellRecord] = {}
        self._formulas: Dict[Tuple[str, str], FormulaRecord] = {}

    # -- seq discipline ----------------------------------------------------
    def _next_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    # -- sheets -------------------------------------------------------------
    def create_sheet(self, sheet_id: Any, name: Any, seq: int) -> SheetRecord:
        sheet_id = _check_id(sheet_id, "sheet_id")
        name = _check_id(name, "name")
        with self._lock:
            seq = self._next_seq(seq)
            if sheet_id in self._sheets:
                raise DuplicateSheetError(f"duplicate sheet_id {sheet_id!r}")
            if name in self._names:
                raise DuplicateSheetError(f"duplicate sheet name {name!r}")
            digest = _pin(
                {"sheet_id": sheet_id, "name": name, "seq": seq,
                 "v": EXCEL_HANDLER_VERSION}
            )
            rec = SheetRecord(sheet_id, name, seq, digest)
            self._sheets[sheet_id] = rec
            self._names[name] = sheet_id
            return rec

    def sheet(self, sheet_id: Any) -> SheetRecord:
        if not isinstance(sheet_id, str) or sheet_id not in self._sheets:
            raise UnknownSheetError(f"unknown sheet {sheet_id!r}")
        return self._sheets[sheet_id]

    def sheet_names(self) -> List[str]:
        return sorted(self._names.keys())

    # -- cells --------------------------------------------------------------
    def cell(self, sheet_id: Any, ref: Any, value: Any, seq: int) -> CellRecord:
        if sheet_id not in self._sheets:
            raise UnknownSheetError(f"unknown sheet {sheet_id!r}")
        canon, _, _ = parse_ref(ref)
        value = _check_value(value, "cell value")
        with self._lock:
            seq = self._next_seq(seq)
            key = (sheet_id, canon)
            if key in self._formulas:
                raise ValidationError(f"{canon} holds a formula, not a value")
            digest = _pin(
                {"sheet_id": sheet_id, "ref": canon, "value": value,
                 "seq": seq, "v": EXCEL_HANDLER_VERSION}
            )
            rec = CellRecord(sheet_id, canon, value, seq, digest)
            self._cells[key] = rec
            return rec

    def cell_value(self, sheet_id: Any, ref: Any) -> Any:
        canon, _, _ = parse_ref(ref)
        rec = self._cells.get((sheet_id, canon))
        return rec.value if rec is not None else None

    # -- formulas -----------------------------------------------------------
    def formula(self, sheet_id: Any, ref: Any, expr: Any, seq: int) -> FormulaRecord:
        if sheet_id not in self._sheets:
            raise UnknownSheetError(f"unknown sheet {sheet_id!r}")
        canon, _, _ = parse_ref(ref)
        func, (c1, r1), (c2, r2) = _parse_formula(expr)
        refs: List[str] = []
        for c in range(c1, c2 + 1):
            for r in range(r1, r2 + 1):
                refs.append(f"{_index_to_col(c)}{r}")
        if canon in refs:
            raise FormulaError("formula may not reference its own cell")
        with self._lock:
            seq = self._next_seq(seq)
            key = (sheet_id, canon)
            if key in self._cells:
                raise ValidationError(f"{canon} already holds a value")
            digest = _pin(
                {"sheet_id": sheet_id, "ref": canon,
                 "expression": expr.strip().upper(), "function": func,
                 "range_refs": refs, "seq": seq, "v": EXCEL_HANDLER_VERSION}
            )
            rec = FormulaRecord(sheet_id, canon, expr.strip().upper(), func,
                                tuple(refs), seq, digest)
            self._formulas[key] = rec
            return rec

    def evaluate(self, sheet_id: Any, ref: Any, seq: int) -> EvalResult:
        if sheet_id not in self._sheets:
            raise UnknownSheetError(f"unknown sheet {sheet_id!r}")
        canon, _, _ = parse_ref(ref)
        frec = self._formulas.get((sheet_id, canon))
        if frec is None:
            raise EvalError(f"{canon} holds no formula")
        nums: List[int] = []
        for rr in frec.range_refs:
            v = self._cells.get((sheet_id, rr))
            if v is None:
                nums.append(0)  # Excel: blanks count as 0
            elif isinstance(v.value, bool) or not isinstance(v.value, int):
                raise EvalError(f"{rr} holds non-numeric value in numeric range")
            else:
                nums.append(v.value)
        if frec.function == "SUM":
            result: Any = sum(nums)
        elif frec.function == "COUNT":
            result = sum(1 for rr in frec.range_refs
                         if self._cells.get((sheet_id, rr)) is not None
                         and isinstance(self._cells[(sheet_id, rr)].value, int)
                         and not isinstance(self._cells[(sheet_id, rr)].value, bool))
        elif not nums:
            raise EvalError("empty range")
        elif frec.function == "AVG":
            # Exact division stays int; otherwise the exact rational pair
            # (numerator, denominator) -- no float contamination.
            total = sum(nums)
            result = total // len(nums) if total % len(nums) == 0 else (total, len(nums))
        elif frec.function == "MIN":
            result = min(nums)
        elif frec.function == "MAX":
            result = max(nums)
        else:  # pragma: no cover - parse guards this
            raise EvalError(f"unknown function {frec.function!r}")
        with self._lock:
            seq = self._next_seq(seq)
            digest = _pin(
                {"sheet_id": sheet_id, "ref": canon,
                 "expression": frec.expression, "value": result,
                 "formula_digest": frec.digest, "seq": seq,
                 "v": EXCEL_HANDLER_VERSION}
            )
            return EvalResult(sheet_id, canon, frec.expression, result,
                              frec.digest, seq, digest)

    # -- views --------------------------------------------------------------
    def sheet_cells(self, sheet_id: Any) -> List[CellRecord]:
        if sheet_id not in self._sheets:
            raise UnknownSheetError(f"unknown sheet {sheet_id!r}")
        return [self._cells[k] for k in sorted(self._cells) if k[0] == sheet_id]


def excel_handler_audit_event(kind: str, seq: int,
                              detail: Mapping[str, Any]) -> Dict[str, Any]:
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
        "version": EXCEL_HANDLER_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    h = ExcelHandler()
    h.create_sheet("s1", "Budget", 0)
    h.cell("s1", "A1", 10, 1)
    h.cell("s1", "A2", 20, 2)
    h.cell("s1", "A3", 30, 3)
    f = h.formula("s1", "B1", "=SUM(A1:A3)", 4)
    assert f.function == "SUM" and len(f.range_refs) == 3
    r = h.evaluate("s1", "B1", 5)
    assert r.value == 60, r.value
    assert excel_handler_audit_event("evaluated", 6, {"ref": "B1"})["schema"] == SCHEMA_PIN
    print("excel-handler OK: sheet, cell, formula, evaluate, audit")


if __name__ == "__main__":
    main()
