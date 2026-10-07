"""Output parser: deterministic structured-output parsing bookkeeping.

Research lineage: LangChain output parsers -- the contract where a
parser declares a format (``get_format_instructions``), ``parse()`` turns
raw model text into a structured value, and ``validate()`` checks an
already-parsed value against the declared schema. This module is the
*bookkeeping* layer for that contract, not an LLM runtime: it records
named parser declarations, makes deterministic parse/validate decisions
over host-supplied text and values, and pins every decision with a
``sha256:`` digest. A booked ``ParseOutcome`` is ledger truth ("the host
supplied this text and the parse decision was this"), never wire truth
about a model's intent.

* **Parser vocabulary** -- six pinned types: ``json-object``,
  ``json-array``, ``csv-row``, ``number``, ``enum``, ``regex``. Each type
  has a fixed spec contract enforced fail-closed at ``register()`` time,
  so a booked parser can always be replayed.
* **Parse semantics** -- ``parse()`` maps host text to a normalized
  value. Content problems are *data* (``success=False`` plus an error
  code like ``bad-json`` or ``no-match``), never raised; only malformed
  *requests* (unknown parser, non-str text, bad seq) raise fail-closed.
* **Validate semantics** -- ``validate()`` checks a host-supplied
  already-parsed value against the parser's declared constraints.
  Verdicts are data (``success`` plus error codes), never raised.
* **Schema semantics** -- ``schema()`` is a pure read view: declared
  type, spec digest, and format instructions (the
  ``get_format_instructions`` analog). It validates seq shape, never
  consumes it, and writes no audit row.
* **Ledger discipline** -- frozen dataclasses, caller-supplied strictly
  increasing int seqs, no wall-clock, RLock-guarded, fail-closed taxonomy.
  A failed mutation consumes its seq (batch-21 discipline) and books an
  ``output-parser.rejected`` audit row; seq rewinds raise bare without
  consuming. Pure views validate seq shape only.
* **Type discipline** -- text, specs and values go through the shared
  canonical normalization: ``bool`` is not ``int``, ``|int| < 2**53``,
  finite floats only, str keys, depth-bounded, length-bounded. Raw text
  and raw values are pinned by digest; the audit boundary carries only
  ids, types, counts, digests and booleans -- never text or values.

Honest scope: this module cannot prove the host's text came from a
model, is complete, or is fresh; a successful parse means "the declared
parser accepted this host-supplied text", never "the model meant this".
Regexes are host-supplied patterns evaluated with ``re.search`` semantics.

Audit: ``output_parser_audit_event()`` builds ``audit.ndjson/1``
records of kinds ``parser-registered`` / ``parsed`` / ``validated`` /
``rejected``. Banned from the audit boundary: ``text``, ``value``,
``values``, ``raw``, ``payload``, ``spec``.

Version pin: output-parser.v1
Schema pin: northstar.output-parser.v1
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

import json  # noqa: E402  (kept after fallback so both paths have json)

#: Module version pin.
OUTPUT_PARSER_VERSION = "output-parser.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.output-parser.v1"

#: Schema tag for audit records emitted by this module.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned parser-type vocabulary (LangChain output-parser shaped).
PARSER_TYPES = (
    "json-object",
    "json-array",
    "csv-row",
    "number",
    "enum",
    "regex",
)

_KINDS = ("parser-registered", "parsed", "validated", "rejected")

_MAX_ID_LEN = 256
_MAX_STR_LEN = 65536
_MAX_DEPTH = 16

_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class OutputParserError(Exception):
    """Base class for output-parser errors."""


class BadParserError(OutputParserError):
    """Malformed parser id."""


class DuplicateParserError(OutputParserError):
    """A parser with this id is already registered."""


class UnknownParserError(OutputParserError):
    """No parser with this id has been registered."""


class BadTypeError(OutputParserError):
    """Parser type outside the pinned vocabulary."""


class BadSpecError(OutputParserError):
    """Spec violates the pinned contract for this parser type."""


class BadTextError(OutputParserError):
    """Malformed text argument (not a str)."""


class BadValueError(OutputParserError):
    """Value is not canonical-normalizable."""


class SeqOrderError(OutputParserError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(OutputParserError):
    """Unknown audit kind or banned keys in the audit detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    """Caller seqs are strictly increasing ints; bools are not ints."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_id(value: Any, name: str, error: type) -> str:
    if not isinstance(value, str):
        raise error(f"{name} must be str, got {type(value).__name__}")
    if not value or not value.strip():
        raise error(f"{name} must be non-empty")
    if len(value) > _MAX_ID_LEN:
        raise error(f"{name} exceeds {_MAX_ID_LEN} chars")
    if any(ch.isspace() for ch in value):
        raise error(f"{name} must not contain whitespace")
    return value


def _normalize(value: Any, depth: int = 0) -> Any:
    """Normalize a value into canonical-JSON-safe form (bool != int)."""
    if depth > _MAX_DEPTH:
        raise BadValueError("value exceeds max nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError("int values must satisfy |n| < 2**53")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError("float values must be finite")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STR_LEN:
            raise BadValueError("str values exceed max length")
        return value
    if isinstance(value, (list, tuple)):
        return [_normalize(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise BadValueError("mapping keys must be str")
            out[k] = _normalize(v, depth + 1)
        return out
    raise BadValueError(f"values must be JSON scalars, got {type(value).__name__}")


def _check_spec(parser_type: str, spec: Any) -> Dict[str, Any]:
    """Enforce the pinned spec contract for a parser type."""
    if spec is None:
        spec = {}
    if not isinstance(spec, Mapping):
        raise BadSpecError("spec must be a mapping")
    normalized = _normalize(dict(spec))

    def _need_str_list(key: str) -> List[str]:
        items = normalized.get(key, [])
        if not isinstance(items, list):
            raise BadSpecError(f"spec {key!r} must be a list")
        for item in items:
            if not isinstance(item, str) or not item:
                raise BadSpecError(f"spec {key!r} members must be non-empty str")
        if len(set(items)) != len(items):
            raise BadSpecError(f"spec {key!r} members must be unique")
        return items

    def _need_opt_number(key: str) -> Any:
        if key not in normalized:
            return None
        v = normalized[key]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise BadSpecError(f"spec {key!r} must be a number")
        return v

    allowed_keys = {
        "json-object": {"required_keys"},
        "json-array": {"max_items", "item_type"},
        "csv-row": {"columns"},
        "number": {"kind", "min", "max"},
        "enum": {"allowed"},
        "regex": {"pattern", "group"},
    }[parser_type]
    for key in normalized:
        if key not in allowed_keys:
            raise BadSpecError(f"spec key {key!r} not allowed for {parser_type}")

    out: Dict[str, Any] = {}
    if parser_type == "json-object":
        out["required_keys"] = _need_str_list("required_keys")
    elif parser_type == "json-array":
        if "max_items" in normalized:
            v = normalized["max_items"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise BadSpecError("spec 'max_items' must be a non-negative int")
            out["max_items"] = v
        if "item_type" in normalized:
            v = normalized["item_type"]
            if v not in ("string", "number", "boolean"):
                raise BadSpecError("spec 'item_type' must be string/number/boolean")
            out["item_type"] = v
    elif parser_type == "csv-row":
        if "columns" in normalized:
            v = normalized["columns"]
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                raise BadSpecError("spec 'columns' must be a positive int")
            out["columns"] = v
    elif parser_type == "number":
        if "kind" in normalized:
            if normalized["kind"] not in ("int", "float"):
                raise BadSpecError("spec 'kind' must be int/float")
            out["kind"] = normalized["kind"]
        low = _need_opt_number("min")
        high = _need_opt_number("max")
        if low is not None and high is not None and low > high:
            raise BadSpecError("spec 'min' must not exceed 'max'")
        if low is not None:
            out["min"] = low
        if high is not None:
            out["max"] = high
    elif parser_type == "enum":
        if "allowed" not in normalized:
            raise BadSpecError("enum spec requires 'allowed'")
        allowed = _need_str_list("allowed")
        if not allowed:
            raise BadSpecError("enum spec 'allowed' must be non-empty")
        out["allowed"] = allowed
    elif parser_type == "regex":
        if "pattern" not in normalized:
            raise BadSpecError("regex spec requires 'pattern'")
        pattern = normalized["pattern"]
        if not isinstance(pattern, str) or not pattern:
            raise BadSpecError("regex spec 'pattern' must be a non-empty str")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise BadSpecError(f"regex pattern does not compile: {exc}") from exc
        if compiled.groups < 0:  # pragma: no cover - defensive
            raise BadSpecError("regex pattern has invalid group count")
        out["pattern"] = pattern
        if "group" in normalized:
            v = normalized["group"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise BadSpecError("spec 'group' must be a non-negative int")
            if v > compiled.groups:
                raise BadSpecError("spec 'group' exceeds pattern group count")
            out["group"] = v
        else:
            out["group"] = 1 if compiled.groups else 0
    return out


def _digest(parts: Tuple[Any, ...]) -> str:
    """Type-tagged sha256 digest pin over canonical JSON."""
    return "sha256:" + jcs_sha256_hex([OUTPUT_PARSER_VERSION, list(parts)])


def output_parser_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for output parsing.

    ``detail`` may carry ids, parser types, counts, digests, error codes
    and booleans -- never raw text, values or specs.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"text", "value", "values", "raw", "payload", "spec"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": OUTPUT_PARSER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParserRecord:
    """Frozen record of a ``register()`` mutation.

    ``spec_json`` is the canonical-JSON encoding of the normalized spec --
    replayable without re-entering host values.
    """

    parser_id: str
    parser_type: str
    spec_json: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (self.parser_id, self.parser_type, self.spec_json, self.seq)
        )

    def spec(self) -> Dict[str, Any]:
        """Parse the canonical spec back into a mapping."""
        return json.loads(self.spec_json)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parser_id": self.parser_id,
            "parser_type": self.parser_type,
            "spec_json": self.spec_json,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ParseOutcome:
    """Frozen record of a ``parse()`` decision.

    Content problems are data: ``success=False`` with an ``error_code``.
    ``value_json`` is the canonical encoding of the normalized value
    (``"null"`` when parsing failed).
    """

    parser_id: str
    outcome_id: str
    success: bool
    value_json: str
    value_digest: str
    error_code: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (
                self.parser_id,
                self.outcome_id,
                self.success,
                self.value_json,
                self.value_digest,
                self.error_code,
                self.seq,
            )
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parser_id": self.parser_id,
            "outcome_id": self.outcome_id,
            "success": self.success,
            "value_json": self.value_json,
            "value_digest": self.value_digest,
            "error_code": self.error_code,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ValidationOutcome:
    """Frozen record of a ``validate()`` decision.

    Verdicts are data: ``success`` plus a tuple of error codes.
    """

    parser_id: str
    success: bool
    errors: Tuple[str, ...]
    value_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (self.parser_id, self.success, self.errors, self.value_digest, self.seq)
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parser_id": self.parser_id,
            "success": self.success,
            "errors": list(self.errors),
            "value_digest": self.value_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SchemaReport:
    """Frozen pure-read view of a parser's declared schema."""

    parser_id: str
    parser_type: str
    spec_digest: str
    instructions: str
    seq: int
    digest: str

    def verify(self) -> bool:
        """Recompute the digest pin."""
        return self.digest == _digest(
            (
                self.parser_id,
                self.parser_type,
                self.spec_digest,
                self.instructions,
                self.seq,
            )
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parser_id": self.parser_id,
            "parser_type": self.parser_type,
            "spec_digest": self.spec_digest,
            "instructions": self.instructions,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Pure parsing / validation logic
# ---------------------------------------------------------------------------


class _BadJson(Exception):
    """Sentinel: json.loads hit a non-finite constant or bad text."""


def _load_json(text: str) -> Any:
    def _const(name: str) -> Any:
        raise _BadJson(name)

    return json.loads(text, parse_constant=_const)


def _parse_json_object(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    try:
        value = _load_json(text)
    except (ValueError, _BadJson):
        return False, None, "bad-json"
    if not isinstance(value, dict):
        return False, None, "not-an-object"
    try:
        return True, _normalize(value), ""
    except BadValueError:
        return False, None, "bad-value"


def _parse_json_array(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    try:
        value = _load_json(text)
    except (ValueError, _BadJson):
        return False, None, "bad-json"
    if not isinstance(value, list):
        return False, None, "not-an-array"
    try:
        normalized = _normalize(value)
    except BadValueError:
        return False, None, "bad-value"
    return True, normalized, ""


def _parse_csv_row(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return False, None, "bad-csv"
    row = rows[0] if rows else []
    if not row:
        return False, None, "empty-row"
    if "columns" in spec and len(row) != spec["columns"]:
        return False, None, "bad-columns"
    try:
        return True, _normalize(row), ""
    except BadValueError:
        return False, None, "bad-value"


def _parse_number(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    stripped = text.strip()
    if not stripped:
        return False, None, "empty-text"
    value: Any = None
    is_int = False
    if _INT_RE.match(stripped):
        try:
            value = int(stripped)
        except ValueError:
            return False, None, "not-a-number"
        is_int = True
        if abs(value) >= 2**53:
            return False, None, "out-of-range"
    elif _FLOAT_RE.match(stripped):
        try:
            value = float(stripped)
        except ValueError:
            return False, None, "not-a-number"
        if value != value or value in (float("inf"), float("-inf")):
            return False, None, "out-of-range"
    else:
        return False, None, "not-a-number"
    kind = spec.get("kind")
    if kind == "int" and not is_int:
        return False, None, "wrong-type"
    if kind == "float" and is_int:
        value = float(value)
    low = spec.get("min")
    high = spec.get("max")
    if low is not None and value < low:
        return False, None, "out-of-range"
    if high is not None and value > high:
        return False, None, "out-of-range"
    return True, value, ""


def _parse_enum(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    stripped = text.strip()
    if not stripped:
        return False, None, "empty-text"
    if stripped not in spec["allowed"]:
        return False, None, "unknown-enum"
    return True, stripped, ""


def _parse_regex(text: str, spec: Dict[str, Any]) -> Tuple[bool, Any, str]:
    if not text:
        return False, None, "empty-text"
    match = re.compile(spec["pattern"]).search(text)
    if match is None:
        return False, None, "no-match"
    extracted = match.group(spec["group"])
    try:
        return True, _normalize(extracted), ""
    except BadValueError:
        return False, None, "bad-value"


def _parse_by_type(
    parser_type: str, text: str, spec: Dict[str, Any]
) -> Tuple[bool, Any, str]:
    if parser_type == "json-object":
        return _parse_json_object(text, spec)
    if parser_type == "json-array":
        return _parse_json_array(text, spec)
    if parser_type == "csv-row":
        return _parse_csv_row(text, spec)
    if parser_type == "number":
        return _parse_number(text, spec)
    if parser_type == "enum":
        return _parse_enum(text, spec)
    if parser_type == "regex":
        return _parse_regex(text, spec)
    raise BadTypeError(f"unknown parser type {parser_type!r}")  # pragma: no cover


def _tag(value: Any) -> Tuple[str, Any]:
    """Type-tagged equality key: bool is not int."""
    if value is None:
        return ("none", 0)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    return ("other", repr(value))


def _validate_by_type(
    parser_type: str, value: Any, spec: Dict[str, Any]
) -> Tuple[bool, Tuple[str, ...]]:
    """Validate a normalized value against a parser's spec; verdicts as data."""
    errors: List[str] = []
    if parser_type == "json-object":
        if not isinstance(value, dict):
            errors.append("wrong-type")
        else:
            for key in spec.get("required_keys", []):
                if key not in value:
                    errors.append("missing-keys")
                    break
    elif parser_type == "json-array":
        if not isinstance(value, list):
            errors.append("wrong-type")
        else:
            if "max_items" in spec and len(value) > spec["max_items"]:
                errors.append("too-many-items")
            item_type = spec.get("item_type")
            if item_type is not None:
                want = {"string": "str", "number": ("int", "float"), "boolean": "bool"}[
                    item_type
                ]
                for item in value:
                    tag = _tag(item)[0]
                    if isinstance(want, tuple):
                        ok = tag in want
                    else:
                        ok = tag == want
                    if not ok:
                        errors.append("bad-item-type")
                        break
    elif parser_type == "csv-row":
        if not isinstance(value, list) or any(
            not isinstance(cell, str) for cell in value
        ):
            errors.append("wrong-type")
        elif "columns" in spec and len(value) != spec["columns"]:
            errors.append("bad-columns")
    elif parser_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append("wrong-type")
        else:
            if spec.get("kind") == "int" and not isinstance(value, int):
                errors.append("wrong-type")
            low = spec.get("min")
            high = spec.get("max")
            if low is not None and value < low:
                errors.append("out-of-range")
            if high is not None and value > high:
                errors.append("out-of-range")
    elif parser_type == "enum":
        if not isinstance(value, str) or value not in spec["allowed"]:
            errors.append("not-allowed")
    elif parser_type == "regex":
        if not isinstance(value, str):
            errors.append("wrong-type")
        elif re.compile(spec["pattern"]).search(value) is None:
            errors.append("no-match")
    else:  # pragma: no cover - vocabulary pinned at register()
        raise BadTypeError(f"unknown parser type {parser_type!r}")
    return (len(errors) == 0, tuple(errors))


def _format_instructions(parser_type: str, spec: Dict[str, Any]) -> str:
    """The get_format_instructions analog: pinned per parser type."""
    if parser_type == "json-object":
        keys = spec.get("required_keys", [])
        suffix = f" It must contain the keys: {', '.join(keys)}." if keys else ""
        return f"Respond with a single JSON object.{suffix}"
    if parser_type == "json-array":
        return "Respond with a single JSON array."
    if parser_type == "csv-row":
        cols = spec.get("columns")
        suffix = f" with exactly {cols} columns" if cols is not None else ""
        return f"Respond with a single comma-separated row{suffix}."
    if parser_type == "number":
        kind = spec.get("kind")
        suffix = f" ({kind})" if kind else ""
        return f"Respond with a single number{suffix}."
    if parser_type == "enum":
        return "Respond with exactly one of: " + ", ".join(spec["allowed"]) + "."
    if parser_type == "regex":
        return "Respond with text matching: " + spec["pattern"] + "."
    raise BadTypeError(f"unknown parser type {parser_type!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# OutputParser ledger
# ---------------------------------------------------------------------------


class OutputParser:
    """Deterministic structured-output parsing bookkeeping (LangChain-shaped)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._parsers: Dict[str, ParserRecord] = {}
        self._outcomes: Dict[str, ParseOutcome] = {}
        self._parse_n = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        """Claim a mutation seq: strictly increasing, else bare raise."""
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must exceed {self._seq}, got {seq}")
        self._seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        """Book a rejected-mutation audit row (seq already consumed)."""
        self._audit.append(
            output_parser_audit_event("rejected", {"reason": reason}, seq)
        )

    # -- mutations ----------------------------------------------------------

    def register(
        self, parser_id: str, parser_type: str, seq: int, spec: Optional[Mapping[str, Any]] = None
    ) -> ParserRecord:
        """Declare a named parser with a pinned type and spec contract."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(parser_id, "parser_id", BadParserError)
                if not isinstance(parser_type, str) or parser_type not in PARSER_TYPES:
                    raise BadTypeError(
                        f"parser_type must be one of {PARSER_TYPES}"
                    )
                normalized = _check_spec(parser_type, spec)
                if parser_id in self._parsers:
                    raise DuplicateParserError(
                        f"parser {parser_id!r} already registered"
                    )
            except OutputParserError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            spec_json = jcs_canonical_json(normalized).decode("utf-8")
            record = ParserRecord(
                parser_id=parser_id,
                parser_type=parser_type,
                spec_json=spec_json,
                seq=seq,
                digest=_digest((parser_id, parser_type, spec_json, seq)),
            )
            self._parsers[parser_id] = record
            self._audit.append(
                output_parser_audit_event(
                    "parser-registered",
                    {"parser_id": parser_id, "parser_type": parser_type},
                    seq,
                )
            )
            return record

    def parse(self, parser_id: str, text: str, seq: int) -> ParseOutcome:
        """Parse host text with a registered parser.

        Content problems are data (``success=False`` + error code); only
        malformed requests raise.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(parser_id, "parser_id", BadParserError)
                if parser_id not in self._parsers:
                    raise UnknownParserError(f"unknown parser {parser_id!r}")
                if not isinstance(text, str):
                    raise BadTextError(
                        f"text must be str, got {type(text).__name__}"
                    )
                if len(text) > _MAX_STR_LEN:
                    raise BadTextError("text exceeds max length")
            except OutputParserError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = self._parsers[parser_id]
            spec = record.spec()
            ok, value, error_code = _parse_by_type(record.parser_type, text, spec)
            if ok:
                value_json = jcs_canonical_json(value).decode("utf-8")
            else:
                value_json = "null"
            value_digest = _digest(("value", value_json))
            self._parse_n += 1
            outcome_id = f"parse-{self._parse_n}"
            outcome = ParseOutcome(
                parser_id=parser_id,
                outcome_id=outcome_id,
                success=ok,
                value_json=value_json,
                value_digest=value_digest,
                error_code=error_code,
                seq=seq,
                digest=_digest(
                    (
                        parser_id,
                        outcome_id,
                        ok,
                        value_json,
                        value_digest,
                        error_code,
                        seq,
                    )
                ),
            )
            self._outcomes[outcome_id] = outcome
            self._audit.append(
                output_parser_audit_event(
                    "parsed",
                    {
                        "parser_id": parser_id,
                        "outcome_id": outcome_id,
                        "success": ok,
                        "error_code": error_code,
                        "value_digest": value_digest,
                    },
                    seq,
                )
            )
            return outcome

    def validate(
        self, parser_id: str, value: Any, seq: int
    ) -> ValidationOutcome:
        """Validate an already-parsed value against a parser's spec.

        Verdicts are data (``success`` + error codes); only malformed
        requests raise.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(parser_id, "parser_id", BadParserError)
                if parser_id not in self._parsers:
                    raise UnknownParserError(f"unknown parser {parser_id!r}")
                normalized = _normalize(value)
            except OutputParserError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            record = self._parsers[parser_id]
            ok, errors = _validate_by_type(
                record.parser_type, normalized, record.spec()
            )
            value_json = jcs_canonical_json(normalized).decode("utf-8")
            value_digest = _digest(("value", value_json))
            outcome = ValidationOutcome(
                parser_id=parser_id,
                success=ok,
                errors=errors,
                value_digest=value_digest,
                seq=seq,
                digest=_digest(
                    (parser_id, ok, errors, value_digest, seq)
                ),
            )
            self._audit.append(
                output_parser_audit_event(
                    "validated",
                    {
                        "parser_id": parser_id,
                        "success": ok,
                        "errors": len(errors),
                        "value_digest": value_digest,
                    },
                    seq,
                )
            )
            return outcome

    # -- views (pure reads; seq shape validated, never consumed) --------------

    def schema(self, parser_id: str, seq: int) -> SchemaReport:
        """Declared schema view: type, spec digest, format instructions."""
        with self._lock:
            _check_seq(seq)
            _check_id(parser_id, "parser_id", BadParserError)
            if parser_id not in self._parsers:
                raise UnknownParserError(f"unknown parser {parser_id!r}")
            record = self._parsers[parser_id]
            spec = record.spec()
            spec_digest = _digest(("spec", record.spec_json))
            instructions = _format_instructions(record.parser_type, spec)
            return SchemaReport(
                parser_id=parser_id,
                parser_type=record.parser_type,
                spec_digest=spec_digest,
                instructions=instructions,
                seq=seq,
                digest=_digest(
                    (parser_id, record.parser_type, spec_digest, instructions, seq)
                ),
            )

    def parser_record(self, parser_id: str, seq: int) -> Optional[ParserRecord]:
        """Fetch a parser record, or None."""
        with self._lock:
            _check_seq(seq)
            return self._parsers.get(parser_id)

    def parser_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted parser ids."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._parsers))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counts (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "parsers": len(self._parsers),
                "parses": len(self._outcomes),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The booked audit rows (oldest first)."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: register -> parse -> validate -> schema."""
    op = OutputParser()
    op.register("cfg", "json-object", 1, {"required_keys": ["name"]})
    op.register("tags", "csv-row", 2, {"columns": 2})
    op.register("level", "enum", 3, {"allowed": ["low", "high"]})
    op.register("count", "number", 4, {"kind": "int", "min": 0, "max": 10})
    op.register("handle", "regex", 5, {"pattern": r"@(\w+)"})

    good = op.parse("cfg", '{"name": "svc", "port": 8080}', 6)
    assert good.success and good.error_code == "", good.error_code
    assert good.verify()
    assert json.loads(good.value_json)["name"] == "svc"

    bad = op.parse("cfg", "not json", 7)
    assert not bad.success and bad.error_code == "bad-json", bad.error_code
    assert bad.verify()

    assert op.parse("tags", "a,b", 8).success
    assert op.parse("tags", "a,b,c", 9).error_code == "bad-columns"
    assert op.parse("level", "high", 10).success
    assert op.parse("level", "medium", 11).error_code == "unknown-enum"
    assert op.parse("count", "7", 12).success
    assert op.parse("count", "7.5", 13).error_code == "wrong-type"
    assert op.parse("handle", "ping @ops", 14).value_json == '"ops"'
    assert op.parse("handle", "no handle", 15).error_code == "no-match"

    v_ok = op.validate("cfg", {"name": "x"}, 16)
    assert v_ok.success and v_ok.errors == ()
    assert v_ok.verify()
    v_bad = op.validate("cfg", {"other": 1}, 17)
    assert not v_bad.success and v_bad.errors == ("missing-keys",)
    assert v_bad.verify()

    rep = op.schema("level", 18)
    assert rep.verify()
    assert "low, high" in rep.instructions
    assert op.stats(18)["parsers"] == 5
    assert op.stats(19)["parses"] == 10
    kinds = [row["kind"] for row in op.audit_log()]
    assert kinds.count("parser-registered") == 5
    assert kinds.count("parsed") == 10
    assert kinds.count("validated") == 2
    print("output-parser OK: register, parse, validate, schema, pins, audit")


if __name__ == "__main__":
    main()
