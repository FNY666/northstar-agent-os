"""Resume validation: validate resume values before the step re-enters.

What was missing
----------------
``durable_resume.py`` knows the *semantics* of a resume: it is an explicit
``Command(resume=...)``; the step re-enters at the head of the interrupted
step; values are matched to interrupts in order; re-sending the prompt is
not a resume and is refused; a retry clears pending writes first.  What it
does **not** do is check that a resume value is even shaped like what the
step asked for -- a wrong-typed or field-missing value goes straight into
the step.  It also offers no way for a caller to ask "what is this run
waiting for, and what does each pending interrupt want?".

``approval_sla.py`` is the complementary half: it says *how long* a human
has to answer ("wait until"), and it fails closed on silence.  This module
says *what* is being waited on ("wait for this") and refuses a malformed
answer.

The source
----------
LangGraph Interrupts, official documentation, sections "Define an interrupt
response schema" and "Rules of interrupts" (read in full 2026-11-14):
https://docs.langchain.com/oss/javascript/langgraph/interrupts

Verbatim from the source (the load-bearing points):

* a ``responseSchema`` option describes the input expected when resuming;
  the client may use the schema to render a typed input form;
* with a Zod schema, ``interrupt()`` returns the parsed value -- the doc's
  example is ``{ approved: true, note: "" }``, the empty-string ``note``
  being the field's default -- and invalid input raises a ``ZodError``;
  the caller retries with a corrected ``new Command({ resume: ... })``
  using the same thread ID;
* a JSON Schema object may also be passed as ``responseSchema``; LangGraph
  exposes that object unchanged but does **not** validate the resume value
  against it; omitting ``responseSchema`` means the interrupt has no
  ``response_schema`` field and resume values pass through without
  validation;
* when several interrupts are pending, a single invocation may resume
  several of them: map each interrupt ID to its resume value, so that every
  response is matched to the right interrupt;
* rules of interrupts: an interrupt pauses by throwing a special exception,
  so a ``try``/``catch`` around it swallows the pause; multiple interrupts
  are matched strictly index-based, so the order of interrupts inside a
  node must stay deterministic; side effects before an interrupt must be
  idempotent, because the node re-runs.

Northstar extensions (explicitly **not** from the source)
--------------------------------------------------------
* **The schema shape.**  No Zod, no ``npm``: the schema here is a plain
  declarative mapping -- required field names, per-field type, numeric
  bounds, enumerated values, optional defaults -- parsed with the standard
  library only.
* **Declared means validated.**  The source explicitly leaves JSON Schema
  objects *unvalidated*; that behaviour is **not** adopted.  In this module
  a declared schema is always enforced, and only an interrupt declared
  *without* a schema passes its value straight through (which is the
  source's "omit ``responseSchema``" behaviour, kept as the Northstar
  default for interrupts that genuinely take free-form input).
* **The gate's position.**  Validation happens *before* the step re-enters.
  This module validates and lists; it never re-runs a step.  Re-entry
  remains ``durable_resume.py``'s job, and this module does not modify it.
* **Fail-closed whole-call semantics.**  The source's retry story is
  "correct the value and send a new Command".  Here that is made a rule:
  a rejected validation consumes *nothing* -- no interrupt leaves the
  pending list, and the caller retries with the same run.

``durable_resume.py`` and ``approval_sla.py`` are read-only reuse: this
module may be handed a run id and asked what is pending, but it never
modifies either file.

Scope: this module is a pure bookkeeping and validation library.  It does
not run a loop, does not talk to a provider, and observes no live run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

__all__ = [
    "RESUME_VALIDATION_VERSION",
    "ResumeValidationError",
    "UnknownInterruptError",
    "DuplicateInterruptError",
    "PayloadNotSerializableError",
    "InvalidSchemaError",
    "SchemaViolationError",
    "InterruptExpiredError",
    "InterruptAlreadyResolvedError",
    "FieldSpec",
    "ResponseSchema",
    "InterruptDeclaration",
    "ResolvedInterrupt",
    "ResumeValidator",
]

#: Version pin for this module's record shapes.
RESUME_VALIDATION_VERSION = "resume-validation.v1"


# ---------------------------------------------------------------------------
# Errors: every one of them is a refusal
# ---------------------------------------------------------------------------


class ResumeValidationError(ValueError):
    """Base class for every refusal this module makes."""


class UnknownInterruptError(ResumeValidationError):
    """A resume addressed an interrupt id that is not pending."""


class DuplicateInterruptError(ResumeValidationError):
    """An interrupt id was declared twice."""


class PayloadNotSerializableError(ResumeValidationError):
    """The interrupt payload is not JSON-serializable."""


class InvalidSchemaError(ResumeValidationError):
    """The declared response schema is malformed."""


class SchemaViolationError(ResumeValidationError):
    """A resume value does not satisfy its declared response schema."""


class InterruptExpiredError(ResumeValidationError):
    """The interrupt expired; expiry never turns into consent."""


class InterruptAlreadyResolvedError(ResumeValidationError):
    """The interrupt was already resolved; it is consumed exactly once."""


# ---------------------------------------------------------------------------
# The declarative schema
# ---------------------------------------------------------------------------

#: Field types this module understands.  ``number`` accepts int or float;
#: ``int`` rejects ``bool`` even though ``bool`` is an ``int`` subclass.
SUPPORTED_TYPES = (
    "bool",
    "int",
    "float",
    "number",
    "str",
    "list",
    "dict",
    "object",
    "any",
)

_NUMERIC_TYPES = ("int", "float", "number")


@dataclass(frozen=True)
class FieldSpec:
    """One field of a declarative response schema.

    ``type`` is one of :data:`SUPPORTED_TYPES`.  ``default`` is the value
    filled in when the field is absent from a resume value -- the source's
    ``{ approved: true, note: "" }`` example has exactly this shape: a
    defaulted ``note`` that the caller may omit.  ``minimum`` /
    ``maximum`` bound a numeric field, and ``enum`` restricts a field to a
    fixed set of values.
    """

    type: str = "any"
    default: Any = None
    has_default: bool = False
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    enum: Optional[tuple[Any, ...]] = None

    @classmethod
    def from_mapping(cls, name: str, raw: Mapping[str, Any]) -> "FieldSpec":
        if not isinstance(raw, Mapping):
            raise InvalidSchemaError(
                f"field {name!r} must be a mapping, got {type(raw).__name__}"
            )
        kind = raw.get("type", "any")
        if kind not in SUPPORTED_TYPES:
            raise InvalidSchemaError(
                f"field {name!r} has unknown type {kind!r}; "
                f"supported: {', '.join(SUPPORTED_TYPES)}"
            )
        has_default = "default" in raw
        default = raw.get("default")
        minimum = raw.get("minimum")
        maximum = raw.get("maximum")
        for bound_name, bound in (("minimum", minimum), ("maximum", maximum)):
            if bound is None:
                continue
            if isinstance(bound, bool) or not isinstance(bound, (int, float)):
                raise InvalidSchemaError(
                    f"field {name!r} {bound_name} must be a number, "
                    f"got {type(bound).__name__}"
                )
            if kind in _NUMERIC_TYPES:
                if isinstance(bound, float):
                    if bound != bound:
                        raise InvalidSchemaError(
                            f"field {name!r} {bound_name} must be a finite number"
                        )
                    if bound == float("inf"):
                        raise InvalidSchemaError(
                            f"field {name!r} {bound_name} must be a finite number"
                        )
                    if bound == float("-inf"):
                        raise InvalidSchemaError(
                            f"field {name!r} {bound_name} must be a finite number"
                        )
        if minimum is not None and maximum is not None and minimum > maximum:
            raise InvalidSchemaError(
                f"field {name!r} minimum {minimum} is above maximum {maximum}"
            )
        if kind not in _NUMERIC_TYPES and (minimum is not None or maximum is not None):
            raise InvalidSchemaError(
                f"field {name!r} of type {kind!r} cannot carry numeric bounds"
            )
        enum_raw = raw.get("enum")
        enum: Optional[tuple[Any, ...]] = None
        if enum_raw is not None:
            if not isinstance(enum_raw, (list, tuple)):
                raise InvalidSchemaError(
                    f"field {name!r} enum must be a list, got {type(enum_raw).__name__}"
                )
            if not enum_raw:
                raise InvalidSchemaError(f"field {name!r} enum must not be empty")
            enum = tuple(enum_raw)
        return cls(
            type=kind,
            default=default,
            has_default=has_default,
            minimum=minimum,
            maximum=maximum,
            enum=enum,
        )

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type}
        if self.has_default:
            out["default"] = self.default
        if self.minimum is not None:
            out["minimum"] = self.minimum
        if self.maximum is not None:
            out["maximum"] = self.maximum
        if self.enum is not None:
            out["enum"] = list(self.enum)
        return out


@dataclass(frozen=True)
class ResponseSchema:
    """A declarative response schema for one interrupt.

    ``fields`` maps a field name to its :class:`FieldSpec`; ``required``
    names the fields that must be present.  A required field that carries a
    default is satisfied by that default, exactly as the source's Zod
    schema satisfies its defaulted ``note``.
    """

    fields: Mapping[str, FieldSpec] = field(default_factory=dict)
    required: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ResponseSchema":
        if not isinstance(raw, Mapping):
            raise InvalidSchemaError(
                f"response schema must be a mapping, got {type(raw).__name__}"
            )
        fields_raw = raw.get("fields", {})
        if not isinstance(fields_raw, Mapping):
            raise InvalidSchemaError(
                f"response schema fields must be a mapping, "
                f"got {type(fields_raw).__name__}"
            )
        fields = {
            str(name): FieldSpec.from_mapping(str(name), spec)
            for name, spec in fields_raw.items()
        }
        required_raw = raw.get("required", ())
        if isinstance(required_raw, str):
            required_raw = (required_raw,)
        if not isinstance(required_raw, (list, tuple)):
            raise InvalidSchemaError(
                f"response schema required must be a list, "
                f"got {type(required_raw).__name__}"
            )
        required: list[str] = []
        for name in required_raw:
            if name not in fields:
                raise InvalidSchemaError(
                    f"required field {name!r} has no field specification"
                )
            if name not in required:
                required.append(str(name))
        return cls(fields=fields, required=tuple(required))

    def as_dict(self) -> dict[str, Any]:
        return {
            "fields": {name: spec.as_dict() for name, spec in self.fields.items()},
            "required": list(self.required),
        }


@dataclass(frozen=True)
class InterruptDeclaration:
    """One declared interrupt: what it asked for and what it expects back."""

    interrupt_id: str
    payload: Any
    response_schema: Optional[ResponseSchema]
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "interrupt_id": self.interrupt_id,
            "payload": self.payload,
            "response_schema": (
                None if self.response_schema is None else self.response_schema.as_dict()
            ),
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ResolvedInterrupt:
    """The record of one interrupt that has been consumed."""

    interrupt_id: str
    value: Any
    seq: int

    def as_dict(self) -> dict[str, Any]:
        return {"interrupt_id": self.interrupt_id, "value": self.value, "seq": self.seq}


# ---------------------------------------------------------------------------
# The validator
# ---------------------------------------------------------------------------


def _check_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResumeValidationError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _type_matches(value: Any, kind: str) -> bool:
    if kind == "any":
        return True
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "float":
        return isinstance(value, float) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "str":
        return isinstance(value, str)
    if kind == "list":
        return isinstance(value, list)
    if kind == "dict":
        return isinstance(value, dict)
    if kind == "object":
        return isinstance(value, Mapping)
    return False


class ResumeValidator:
    """The pending-interrupt list and the resume-value validation gate.

    The gate sits *before* a step re-enters: :meth:`validate_resume`
    checks the whole batch of resume values, and only a batch that passes
    completely yields values that :meth:`resolve` will consume.  A rejected
    batch consumes nothing -- every interrupt stays pending, so the caller
    can correct the value and retry against the same run.
    """

    def __init__(self) -> None:
        self._pending: dict[str, InterruptDeclaration] = {}
        self._resolved: dict[str, ResolvedInterrupt] = {}
        self._expired: dict[str, InterruptDeclaration] = {}
        self._known: set[str] = set()

    # -- declaring --------------------------------------------------------

    def declare(
        self,
        interrupt_id: str,
        payload: Any,
        response_schema: Any = None,
        seq: int = 0,
    ) -> InterruptDeclaration:
        """Register one pending interrupt.

        ``payload`` must be JSON-serializable -- it is the value the step
        asked for, and it has to survive a checkpoint round-trip.
        ``response_schema`` may be ``None`` (the value passes through
        unvalidated, the source's "omit ``responseSchema``" case) or a
        mapping describing the expected resume value.  A duplicate id is
        refused: an interrupt is declared once.
        """
        _check_text(interrupt_id, "interrupt_id")
        _check_seq(seq, "seq")
        if interrupt_id in self._known:
            raise DuplicateInterruptError(
                f"interrupt {interrupt_id!r} is already declared"
            )
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as error:
            raise PayloadNotSerializableError(
                f"interrupt {interrupt_id!r} payload is not JSON-serializable: {error}"
            ) from error
        schema: Optional[ResponseSchema]
        if response_schema is None:
            schema = None
        elif isinstance(response_schema, ResponseSchema):
            schema = response_schema
        else:
            schema = ResponseSchema.from_mapping(response_schema)
        declaration = InterruptDeclaration(
            interrupt_id=interrupt_id,
            payload=payload,
            response_schema=schema,
            seq=seq,
        )
        self._pending[interrupt_id] = declaration
        self._known.add(interrupt_id)
        return declaration

    # -- listing ----------------------------------------------------------

    def pending(self) -> list[InterruptDeclaration]:
        """Every interrupt still waiting for a resume value.

        This is the ``__interrupt__`` equivalent: id, the payload the step
        asked for, and the schema the answer must satisfy.  An empty list
        means the run is waiting for nothing.
        """
        return sorted(self._pending.values(), key=lambda item: item.seq)

    def resolved(self) -> list[ResolvedInterrupt]:
        """The interrupts already consumed, in resolution order."""
        return sorted(self._resolved.values(), key=lambda item: item.seq)

    def expired(self) -> list[InterruptDeclaration]:
        """The interrupts the caller marked expired."""
        return sorted(self._expired.values(), key=lambda item: item.seq)

    def get(self, interrupt_id: str) -> InterruptDeclaration:
        """Return a pending declaration. Raises ``KeyError`` if unknown."""
        try:
            return self._pending[interrupt_id]
        except KeyError:
            raise KeyError(f"unknown interrupt {interrupt_id!r}") from None

    # -- validating -------------------------------------------------------

    def validate_resume(
        self, resume_map: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate a whole batch of resume values.

        ``resume_map`` maps an interrupt id to the value the caller sends
        back.  Every id must be pending, and every value must satisfy that
        interrupt's schema.  Returns the validated values (schema defaults
        filled in) keyed by interrupt id.

        The batch is all-or-nothing: an unknown id or a schema violation
        raises, and **nothing is consumed** -- no interrupt leaves the
        pending list, and the caller retries with the same run and a
        corrected value.
        """
        if not isinstance(resume_map, Mapping):
            raise ResumeValidationError(
                f"resume_map must be a mapping, got {type(resume_map).__name__}"
            )
        # First pass: every id must be known and pending.  An expired or
        # already-resolved id is not resumable either.
        for interrupt_id in resume_map:
            _check_text(interrupt_id, "interrupt id")
            if interrupt_id in self._expired:
                raise InterruptExpiredError(
                    f"interrupt {interrupt_id!r} expired; expiry never consents"
                )
            if interrupt_id in self._resolved:
                raise InterruptAlreadyResolvedError(
                    f"interrupt {interrupt_id!r} is already resolved"
                )
            if interrupt_id not in self._pending:
                raise UnknownInterruptError(
                    f"unknown interrupt {interrupt_id!r} is not pending"
                )
        # Second pass: validate every value.  A failure aborts the whole
        # batch before any value is accepted.
        validated: dict[str, Any] = {}
        for interrupt_id, value in resume_map.items():
            declaration = self._pending[interrupt_id]
            validated[interrupt_id] = self._validate_value(declaration, value)
        return validated

    def _validate_value(
        self, declaration: InterruptDeclaration, value: Any
    ) -> Any:
        """Validate one resume value against its declaration's schema."""
        schema = declaration.response_schema
        if schema is None:
            # No schema declared: the value passes through unvalidated.
            return value
        if not isinstance(value, Mapping):
            raise SchemaViolationError(
                f"interrupt {declaration.interrupt_id!r} expects a mapping, "
                f"got {type(value).__name__}"
            )
        out: dict[str, Any] = {}
        for name in schema.required:
            if name in value:
                out[name] = value[name]
            elif schema.fields[name].has_default:
                out[name] = schema.fields[name].default
            else:
                raise SchemaViolationError(
                    f"interrupt {declaration.interrupt_id!r} is missing "
                    f"required field {name!r}"
                )
        for name, spec in schema.fields.items():
            if name not in out:
                if name not in value:
                    if spec.has_default:
                        out[name] = spec.default
                    continue
                out[name] = value[name]
            candidate = out[name]
            if not _type_matches(candidate, spec.type):
                raise SchemaViolationError(
                    f"interrupt {declaration.interrupt_id!r} field {name!r} "
                    f"must be of type {spec.type}, got {type(candidate).__name__}"
                )
            if spec.enum is not None and candidate not in spec.enum:
                raise SchemaViolationError(
                    f"interrupt {declaration.interrupt_id!r} field {name!r} "
                    f"must be one of {list(spec.enum)}, got {candidate!r}"
                )
            if spec.type in _NUMERIC_TYPES and candidate is not None:
                if spec.minimum is not None and candidate < spec.minimum:
                    raise SchemaViolationError(
                        f"interrupt {declaration.interrupt_id!r} field {name!r} "
                        f"is below the minimum {spec.minimum}"
                    )
                if spec.maximum is not None and candidate > spec.maximum:
                    raise SchemaViolationError(
                        f"interrupt {declaration.interrupt_id!r} field {name!r} "
                        f"is above the maximum {spec.maximum}"
                    )
        return out

    # -- consuming --------------------------------------------------------

    def resolve(
        self, interrupt_id: str, validated_value: Any, seq: int = 0
    ) -> ResolvedInterrupt:
        """Consume one interrupt with an already validated value.

        The value is re-checked against the schema here as well, so a
        caller cannot consume an interrupt with a value that
        :meth:`validate_resume` would have refused.  Resolving an
        unknown, already-resolved, or expired interrupt is refused;
        expiry never auto-approves.
        """
        _check_text(interrupt_id, "interrupt_id")
        _check_seq(seq, "seq")
        if interrupt_id in self._expired:
            raise InterruptExpiredError(
                f"interrupt {interrupt_id!r} expired; expiry never consents"
            )
        if interrupt_id in self._resolved:
            raise InterruptAlreadyResolvedError(
                f"interrupt {interrupt_id!r} is already resolved"
            )
        if interrupt_id not in self._pending:
            raise UnknownInterruptError(
                f"unknown interrupt {interrupt_id!r} is not pending"
            )
        declaration = self._pending[interrupt_id]
        checked = self._validate_value(declaration, validated_value)
        del self._pending[interrupt_id]
        record = ResolvedInterrupt(
            interrupt_id=interrupt_id, value=checked, seq=seq
        )
        self._resolved[interrupt_id] = record
        return record

    def mark_expired(self, interrupt_id: str) -> InterruptDeclaration:
        """Mark a pending interrupt expired (the caller decides when).

        An expired interrupt leaves the pending list and can never be
        resolved: silence is not consent.
        """
        _check_text(interrupt_id, "interrupt_id")
        if interrupt_id in self._expired:
            raise InterruptExpiredError(
                f"interrupt {interrupt_id!r} is already expired"
            )
        if interrupt_id in self._resolved:
            raise InterruptAlreadyResolvedError(
                f"interrupt {interrupt_id!r} is already resolved"
            )
        if interrupt_id not in self._pending:
            raise UnknownInterruptError(
                f"unknown interrupt {interrupt_id!r} is not pending"
            )
        declaration = self._pending.pop(interrupt_id)
        self._expired[interrupt_id] = declaration
        return declaration


def main() -> None:
    validator = ResumeValidator()
    validator.declare(
        "approval#0",
        {"question": "approve?"},
        {
            "fields": {
                "approved": {"type": "bool"},
                "note": {"type": "str", "default": ""},
            },
            "required": ["approved"],
        },
        seq=1,
    )
    assert len(validator.pending()) == 1
    validated = validator.validate_resume({"approval#0": {"approved": True}})
    assert validated == {"approval#0": {"approved": True, "note": ""}}
    validator.resolve("approval#0", validated["approval#0"], seq=2)
    assert validator.pending() == []
    print("resume-validation OK: declare/pending/validate/resolve")


if __name__ == "__main__":
    main()
