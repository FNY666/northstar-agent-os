"""Mypy-style type-checking interface (declared signatures vs reported calls).

Research motivation: agents generate and invoke typed interfaces -- tool
schemas, plugin entry points, plan steps with typed arguments -- and a
large share of integration failures are *type* failures (wrong argument
type, missing argument, ``Any`` leaking through an unchecked boundary).
Mypy answers those questions for Python source; this module pins the
deterministic bookkeeping half of that shape for *reported* interfaces.

Distinct from ``type_checker.py`` (batch 14): that module implements the
simply-typed lambda calculus over real ``Term``/``Type`` objects -- it
checks terms. This module never sees code. The host *declares* a function
signature (pinned parameter types and return type) and later *reports*
what the argument types of a call were; the module checks the report
against the declaration and returns frozen verdict records. It is the
interface half of mypy: ``declare_signature()`` / ``check()`` /
``errors()`` / ``strict()``.

- ``TypeCheckerIface`` -- registry of pinned signatures. ``declare_signature()``
  pins a signature (parameter names + pinned type expressions + return
  type). ``check()`` takes a signature id and a host-reported argument
  mapping (param name -> type expression) and returns a frozen
  ``CheckReport``: ``ok`` plus a tuple of ``TypeDiagnostic`` records.
  Diagnostics are *data*, never raised -- a genuine mismatch is a
  verdict, exactly like mypy's error output. ``errors()`` reads back the
  accumulated diagnostic ledger. ``strict(seq, enabled=True)`` flips the
  strict discipline; ``is_strict()`` reads it.
- ``type_checker_iface_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``declared`` / ``checked`` / ``errors-read`` / ``strict-set`` /
  ``rejected``); ids, digests, and type strings only, never argument
  values.

Pinned type vocabulary (mypy-shaped, closed)::

    primitives : int | str | bool | float | None | bytes | Any
    List[T] | Dict[K, V] | Tuple[T1, ...] | Optional[T] | Union[T1, ...]

Type expressions are ``str`` for primitives or tuples whose head is one of
``"List"`` / ``"Dict"`` / ``"Tuple"`` / ``"Optional"`` / ``"Union"``.
``Optional[T]`` is the ``None``-inclusive sugar; ``Union`` needs >= 2
distinct members and may not contain ``Any`` (a union with ``Any`` is
just ``Any`` -- say so). ``Optional[None]`` is refused.

Compatibility (mypy discipline on this fragment):

- ``Any`` is bidirectionally compatible with everything. In strict mode an
  ``Any`` appearing anywhere in a *reported* argument type is additionally
  recorded as an ``any-expr`` diagnostic (mypy's ``warn_return_any`` /
  ``disallow_any_expr`` spirit).
- ``bool`` <: ``int`` (mypy numeric lattice), ``int`` <: ``float``.
- ``Optional[T]`` accepts ``None`` or ``T``; ``Union`` accepts any member.
- ``List`` / ``Dict`` are *invariant* (mypy): element types must match
  modulo ``Any``. ``Tuple`` is checked per-position.
- Reported ``Optional``/``Union`` against a non-union expectation: every
  member must be compatible.

Diagnostic codes (mypy-shaped): ``arg-type`` (incompatible argument),
``call-arg`` (missing or unexpected argument), ``any-expr`` (strict-only).

Fail-closed edges:

- Unknown signature ids raise ``UnknownSignatureError`` (never fabricated);
  duplicate signature ids raise ``DuplicateSignatureError`` (never recycled).
- Malformed type expressions raise ``BadTypeError`` at the boundary
  (declare *and* check -- a bad report is rejected, never checked).
- Non-mapping / non-str-keyed argument reports raise ``BadArgumentError``.
- Non-positive / bool / non-int / non-increasing caller seqs raise
  ``SeqOrderError``. A failed mutation still consumes its seq (fail-closed
  ledger position, same discipline as the batch-21 ``rbac_engine`` module).
- Verdict *failures* (mismatches) are data; only malformed input raises.

Digest pins are ``sha256:`` over type-tagged canonical bodies (bool !=
int, ``|n| >= 2**53`` refused), so identical declarations replay to
identical pins. Diagnostic pins are content-only (no seq), deterministic
across instances.

Honest scope:

- This module books *host-reported* types. It cannot inspect runtime
  values, cannot prove the host's report is true, and emits no code --
  ``ok=True`` means "the reported types fit the pinned signature", never
  "the call was type-safe". Pair with a real checker (mypy, pyright) over
  the actual source for production enforcement.
- The strict discipline currently pins exactly the ``Any`` rule above;
  it is not mypy's full ``--strict`` flag set.
- The type vocabulary is the pinned fragment above -- no callables,
  generics beyond the listed constructors, literals, or protocols.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

#: Module version pin.
TYPE_CHECKER_IFACE_VERSION = "type-checker-iface.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.type-checker-iface.v1"

#: Pinned primitive type names.
PRIMITIVES = ("int", "str", "bool", "float", "None", "bytes", "Any")

#: Pinned container constructor heads.
_CONTAINER_HEADS = ("List", "Dict", "Tuple", "Optional", "Union")

_TYPE_AUDIT_KINDS = (
    "declared",
    "checked",
    "errors-read",
    "strict-set",
    "rejected",
)

_DIAGNOSTIC_CODES = ("arg-type", "call-arg", "any-expr")


class TypeIfaceError(ValueError):
    """Base fail-closed error for the type checker interface."""


class UnknownSignatureError(TypeIfaceError):
    """The signature id is not in the registry."""


class DuplicateSignatureError(TypeIfaceError):
    """The signature id is already registered."""


class BadTypeError(TypeIfaceError):
    """A type expression is not in the pinned vocabulary."""


class BadSignatureError(TypeIfaceError):
    """The signature shape itself is malformed (dup params, bad names...)."""


class BadArgumentError(TypeIfaceError):
    """The reported argument mapping is malformed."""


class SeqOrderError(TypeIfaceError):
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
            raise TypeIfaceError("refused |n| >= 2**53 (JCS float-loss boundary)")
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
    raise TypeIfaceError(f"unpinable type for digest: {type(value).__name__}")


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    h = hashlib.sha256()
    for key, value in parts:
        h.update(_encode_tagged(key))
        h.update(b"\x00")
        h.update(_encode_tagged(value))
        h.update(b"\xff")
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Type expressions
# ---------------------------------------------------------------------------


def _check_name(name: str, what: str) -> str:
    if not isinstance(name, str) or not name:
        raise BadSignatureError(f"{what} must be a non-empty str")
    return name


def _validate_type(expr: object) -> Tuple:
    """Validate a type expression; return its canonical tuple form.

    Canonical form: primitives stay ``str``; containers become tuples
    ``("List", T)`` / ``("Dict", K, V)`` / ``("Tuple", *Ts)`` /
    ``("Optional", T)`` / ``("Union", *Ts)`` with members canonicalized.
    """
    if isinstance(expr, str):
        if expr not in PRIMITIVES:
            raise BadTypeError(f"unknown primitive type: {expr!r}")
        return expr
    if isinstance(expr, tuple) and expr:
        head, rest = expr[0], expr[1:]
        if head == "List" and len(rest) == 1:
            return ("List", _validate_type(rest[0]))
        if head == "Dict" and len(rest) == 2:
            return ("Dict", _validate_type(rest[0]), _validate_type(rest[1]))
        if head == "Tuple" and len(rest) >= 1:
            return ("Tuple",) + tuple(_validate_type(t) for t in rest)
        if head == "Optional" and len(rest) == 1:
            inner = _validate_type(rest[0])
            if inner == "None":
                raise BadTypeError("Optional[None] is refused (use None)")
            return ("Optional", inner)
        if head == "Union" and len(rest) >= 2:
            members = tuple(_validate_type(t) for t in rest)
            if any(m == "Any" for m in members):
                raise BadTypeError("Union may not contain Any (use Any)")
            if len(set(members)) != len(members):
                raise BadTypeError("Union members must be distinct")
            return ("Union",) + members
        raise BadTypeError(f"malformed container type: {expr!r}")
    raise BadTypeError(
        f"type expression must be str or tuple, got {type(expr).__name__}"
    )


def type_to_str(expr: Tuple) -> str:
    """Render a canonical type expression in mypy-ish notation."""
    if isinstance(expr, str):
        return expr
    head = expr[0]
    if head == "List":
        return f"List[{type_to_str(expr[1])}]"
    if head == "Dict":
        return f"Dict[{type_to_str(expr[1])}, {type_to_str(expr[2])}]"
    if head == "Tuple":
        return "Tuple[" + ", ".join(type_to_str(t) for t in expr[1:]) + "]"
    if head == "Optional":
        return f"Optional[{type_to_str(expr[1])}]"
    if head == "Union":
        return "Union[" + ", ".join(type_to_str(t) for t in expr[1:]) + "]"
    raise TypeIfaceError(f"non-canonical type expression: {expr!r}")


def _contains_any(expr: Tuple) -> bool:
    if expr == "Any":
        return True
    if isinstance(expr, tuple):
        return any(_contains_any(t) for t in expr[1:])
    return False


def _equal_mod_any(a: Tuple, b: Tuple) -> bool:
    """Structural equality where Any matches anything (for invariance)."""
    if a == "Any" or b == "Any":
        return True
    if isinstance(a, str) or isinstance(b, str):
        return a == b
    if a[0] != b[0] or len(a) != len(b):
        return False
    return all(_equal_mod_any(x, y) for x, y in zip(a[1:], b[1:]))


def _compatible(reported: Tuple, expected: Tuple) -> bool:
    """Is a reported type acceptable where ``expected`` is declared?"""
    if expected == "Any" or reported == "Any":
        return True
    if isinstance(reported, str) and isinstance(expected, str):
        if reported == expected:
            return True
        if reported == "bool" and expected == "int":
            return True  # bool <: int (mypy numeric lattice)
        if reported == "int" and expected == "float":
            return True  # int <: float (numeric tower)
        return False
    if isinstance(expected, tuple) and expected[0] == "Optional":
        if reported == "None":
            return True
        return _compatible(reported, expected[1])
    if isinstance(expected, tuple) and expected[0] == "Union":
        return any(_compatible(reported, m) for m in expected[1:])
    if isinstance(reported, tuple) and reported[0] in ("Optional", "Union"):
        # A reported union must fit wholly: every member compatible.
        return all(_compatible(m, expected) for m in reported[1:])
    if (
        isinstance(reported, tuple)
        and isinstance(expected, tuple)
        and reported[0] == expected[0]
        and reported[0] in ("List", "Dict")
    ):
        # Invariant constructors (mypy): element types must match mod Any.
        return _equal_mod_any(reported, expected)
    if (
        isinstance(reported, tuple)
        and isinstance(expected, tuple)
        and reported[0] == "Tuple"
        and expected[0] == "Tuple"
        and len(reported) == len(expected)
    ):
        return all(_compatible(r, e) for r, e in zip(reported[1:], expected[1:]))
    return False


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureRecord:
    """A pinned declared function signature."""

    sig_id: str
    func_name: str
    params: Tuple[Tuple[str, Tuple], ...]  # ((name, canonical type), ...)
    returns: Tuple
    pin: str

    def as_dict(self) -> dict:
        return {
            "sig_id": self.sig_id,
            "func_name": self.func_name,
            "params": [(n, type_to_str(t)) for n, t in self.params],
            "returns": type_to_str(self.returns),
            "pin": self.pin,
        }


@dataclass(frozen=True)
class TypeDiagnostic:
    """One mypy-shaped diagnostic, recorded as data (never raised)."""

    code: str  # arg-type | call-arg | any-expr
    message: str
    param: str  # "" when not tied to a parameter
    expected: str  # "" when not applicable
    got: str  # "" when not applicable
    pin: str

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "param": self.param,
            "expected": self.expected,
            "got": self.got,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class CheckReport:
    """Frozen verdict for one reported call against a pinned signature."""

    sig_id: str
    ok: bool
    diagnostics: Tuple[TypeDiagnostic, ...]
    pin: str

    def as_dict(self) -> dict:
        return {
            "sig_id": self.sig_id,
            "ok": self.ok,
            "diagnostics": [d.as_dict() for d in self.diagnostics],
            "pin": self.pin,
        }


@dataclass(frozen=True)
class StrictRecord:
    """Frozen record of a strict-mode change."""

    enabled: bool
    pin: str

    def as_dict(self) -> dict:
        return {"enabled": self.enabled, "pin": self.pin}


# ---------------------------------------------------------------------------
# The interface
# ---------------------------------------------------------------------------


class TypeCheckerIface:
    """Mypy-shaped signature/call checking as deterministic bookkeeping.

    RLock-guarded; caller-supplied strictly-increasing int seqs; no
    wall-clock; fail-closed. ``check()`` verdict failures are data --
    only malformed input raises.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sigs: Dict[str, SignatureRecord] = {}
        self._ledger: Tuple[TypeDiagnostic, ...] = ()
        self._strict = False
        self._last_seq = 0

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        _check_seq_value(seq)
        if seq <= self._last_seq:
            # Failed mutations still consume their seq (fail-closed
            # ledger position): claim first, then raise.
            self._last_seq = seq
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq

    def _require_sig(self, sig_id: str) -> SignatureRecord:
        try:
            return self._sigs[sig_id]
        except KeyError:
            raise UnknownSignatureError(f"unknown signature: {sig_id!r}")

    def _pin_diagnostic(
        self, code: str, message: str, param: str, expected: str, got: str
    ) -> TypeDiagnostic:
        pin = _digest_tagged(
            (
                ("code", code),
                ("message", message),
                ("param", param),
                ("expected", expected),
                ("got", got),
                ("module", TYPE_CHECKER_IFACE_VERSION),
            )
        )
        return TypeDiagnostic(
            code=code,
            message=message,
            param=param,
            expected=expected,
            got=got,
            pin=pin,
        )

    # -- signature registry ----------------------------------------------

    def declare_signature(
        self,
        sig_id: str,
        func_name: str,
        params: Tuple[Tuple[str, object], ...],
        returns: object,
        seq: int,
    ) -> SignatureRecord:
        """Pin a function signature: ordered params + return type."""
        with self._lock:
            self._claim_seq(seq)
            _check_name(sig_id, "sig_id")
            _check_name(func_name, "func_name")
            if sig_id in self._sigs:
                raise DuplicateSignatureError(
                    f"signature already declared: {sig_id!r}"
                )
            if not isinstance(params, tuple):
                raise BadSignatureError("params must be a tuple of (name, type)")
            seen = set()
            canon_params = []
            for item in params:
                if not isinstance(item, tuple) or len(item) != 2:
                    raise BadSignatureError(
                        "each param must be a (name, type) tuple"
                    )
                pname, ptype = item
                _check_name(pname, "param name")
                if pname in seen:
                    raise BadSignatureError(
                        f"duplicate parameter name: {pname!r}"
                    )
                seen.add(pname)
                canon_params.append((pname, _validate_type(ptype)))
            canon_params_t = tuple(canon_params)
            canon_returns = _validate_type(returns)
            pin = _digest_tagged(
                (
                    ("sig_id", sig_id),
                    ("func_name", func_name),
                    (
                        "params",
                        tuple(
                            (n, type_to_str(t)) for n, t in canon_params_t
                        ),
                    ),
                    ("returns", type_to_str(canon_returns)),
                    ("module", TYPE_CHECKER_IFACE_VERSION),
                )
            )
            rec = SignatureRecord(
                sig_id=sig_id,
                func_name=func_name,
                params=canon_params_t,
                returns=canon_returns,
                pin=pin,
            )
            self._sigs[sig_id] = rec
            return rec

    def signature(self, sig_id: str) -> SignatureRecord:
        with self._lock:
            return self._require_sig(sig_id)

    def signature_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sigs))

    # -- checking ----------------------------------------------------------

    def check(
        self,
        sig_id: str,
        args: Mapping[str, object],
        seq: int,
    ) -> CheckReport:
        """Check a host-reported argument mapping against a signature.

        ``args`` maps parameter name -> reported type expression. Returns
        a frozen ``CheckReport``; mismatches are diagnostics (data), only
        malformed input raises.
        """
        with self._lock:
            self._claim_seq(seq)
            sig = self._require_sig(sig_id)
            if not isinstance(args, Mapping):
                raise BadArgumentError("args must be a mapping")
            canon_args: Dict[str, Tuple] = {}
            for name, texpr in args.items():
                if not isinstance(name, str):
                    raise BadArgumentError("arg names must be str")
                canon_args[name] = _validate_type(texpr)

            declared = {n: t for n, t in sig.params}
            diags = []

            for pname in declared:
                if pname not in canon_args:
                    diags.append(
                        self._pin_diagnostic(
                            "call-arg",
                            f'Missing argument "{pname}"',
                            pname,
                            type_to_str(declared[pname]),
                            "",
                        )
                    )
            for pname in canon_args:
                if pname not in declared:
                    diags.append(
                        self._pin_diagnostic(
                            "call-arg",
                            f'Unexpected keyword argument "{pname}"',
                            pname,
                            "",
                            type_to_str(canon_args[pname]),
                        )
                    )
            for pname, expected in declared.items():
                if pname not in canon_args:
                    continue
                got = canon_args[pname]
                if not _compatible(got, expected):
                    diags.append(
                        self._pin_diagnostic(
                            "arg-type",
                            f'Argument "{pname}" has incompatible type '
                            f'"{type_to_str(got)}"; expected '
                            f'"{type_to_str(expected)}"',
                            pname,
                            type_to_str(expected),
                            type_to_str(got),
                        )
                    )
                elif self._strict and _contains_any(got):
                    diags.append(
                        self._pin_diagnostic(
                            "any-expr",
                            f'Argument "{pname}" has type Any in strict mode',
                            pname,
                            type_to_str(expected),
                            type_to_str(got),
                        )
                    )

            diags_t = tuple(diags)
            ok = not diags_t
            pin = _digest_tagged(
                (
                    ("sig_id", sig_id),
                    ("sig_pin", sig.pin),
                    (
                        "args",
                        tuple(
                            (n, type_to_str(canon_args[n]))
                            for n in sorted(canon_args)
                        ),
                    ),
                    ("diagnostics", tuple(d.pin for d in diags_t)),
                    ("ok", ok),
                    ("seq", seq),
                    ("module", TYPE_CHECKER_IFACE_VERSION),
                )
            )
            report = CheckReport(
                sig_id=sig_id, ok=ok, diagnostics=diags_t, pin=pin
            )
            if diags_t:
                self._ledger = self._ledger + diags_t
            return report

    # -- error ledger ------------------------------------------------------

    def errors(self) -> Tuple[TypeDiagnostic, ...]:
        """Read back the accumulated diagnostic ledger (pure view)."""
        with self._lock:
            return self._ledger

    # -- strict mode ---------------------------------------------------------

    def strict(self, seq: int, enabled: bool = True) -> StrictRecord:
        """Set the strict discipline; returns a frozen record of the change."""
        with self._lock:
            self._claim_seq(seq)
            if not isinstance(enabled, bool):
                raise TypeIfaceError("enabled must be bool")
            self._strict = enabled
            pin = _digest_tagged(
                (
                    ("enabled", enabled),
                    ("module", TYPE_CHECKER_IFACE_VERSION),
                )
            )
            return StrictRecord(enabled=enabled, pin=pin)

    def is_strict(self) -> bool:
        with self._lock:
            return self._strict


def type_checker_iface_audit_event(
    kind: str,
    seq: int,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for type-checker-interface activity.

    Carries ids, digests, and type strings only -- never argument values.
    """
    if kind not in _TYPE_AUDIT_KINDS:
        raise TypeIfaceError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise TypeIfaceError("seq must be a positive int")
    if not isinstance(detail, str):
        raise TypeIfaceError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": TYPE_CHECKER_IFACE_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    tc = TypeCheckerIface()
    rec = tc.declare_signature(
        "sig-1",
        "greet",
        (("name", "str"), ("count", "int")),
        "str",
        1,
    )
    assert rec.pin.startswith("sha256:")
    assert type_to_str(rec.params[0][1]) == "str"
    ok_report = tc.check("sig-1", {"name": "str", "count": "int"}, 2)
    assert ok_report.ok and ok_report.diagnostics == ()
    bad = tc.check("sig-1", {"name": "int", "count": "int"}, 3)
    assert not bad.ok and bad.diagnostics[0].code == "arg-type"
    assert len(tc.errors()) == 1
    missing = tc.check("sig-1", {"name": "str"}, 4)
    assert not missing.ok and missing.diagnostics[0].code == "call-arg"
    # bool <: int, int <: float
    tc.declare_signature("sig-2", "f", (("x", "int"), ("y", "float")), "None", 5)
    tower = tc.check("sig-2", {"x": "bool", "y": "int"}, 6)
    assert tower.ok
    # strict: Any becomes a diagnostic
    tc.strict(7)
    assert tc.is_strict()
    tc.declare_signature("sig-3", "g", (("v", "str"),), "None", 8)
    any_rep = tc.check("sig-3", {"v": "Any"}, 9)
    assert not any_rep.ok and any_rep.diagnostics[0].code == "any-expr"
    tc.strict(10, enabled=False)
    assert not tc.is_strict()
    evt = type_checker_iface_audit_event("checked", 1)
    assert evt["schema"] == SCHEMA_PIN
    print(
        "type-checker-iface OK: declare, check, tower, strict, errors, audit"
    )


if __name__ == "__main__":
    main()
