"""EU conformity-assessment / CE-marking-shaped decision ledger.

Research context: placing a product on the EU market under the New
Legislative Framework requires a *conformity assessment* (choosing a module
under the relevant harmonised standard), an *EU declaration of conformity*
(DoC), and the *CE marking* being affixed. Those are declared, documented
decisions: a manufacturer states that the product meets the essential
requirements, the notified body (if any) is identified, and the marking is
applied to the product or its packaging.

This module is the *decision ledger* layer for that lifecycle. It owns the
register -> assess -> declare -> affix flow as a deterministic,
digest-pinned state machine with caller-int seq discipline and an audit
trail. It assesses no product, inspects no test report, identifies no
harmonised standard, and certifies nothing; it books the host's *declared*
decisions in a tamper-evident, seq-ordered form.

What each operation means:

1. ``register_product(product_id, seq, product_class="general",
   product_digest="")`` -- books one product into the ledger under a pinned
   product-class vocabulary. The product description travels as a
   ``sha256:`` digest pin only: raw descriptions, model names, and serial
   numbers never enter a record. Duplicate ids refused fail-closed.
2. ``assess(product_id, seq, module="a", verdict="conformant",
   standard_digest="")`` -- books one declared conformity assessment,
   minted as ``asm-N``, over the pinned EU assessment-module vocabulary
   (``a`` / ``a1`` / ``a2`` / ``b`` / ``c`` / ``c1`` / ``c2`` / ``d`` /
   ``d1`` / ``e`` / ``e1`` / ``f`` / ``f1`` / ``g`` / ``h`` / ``h1``). The
   verdict is pinned to ``conformant`` / ``non-conformant`` / ``conditional``
   and booked **as data** (a host declaration, never proof the product is
   conformant). The harmonised standard travels as a digest pin only.
   Assessments are repeatable: re-assessing books a new record and history
   is kept.
3. ``declare(product_id, seq, declaration_digest="")`` -- books one EU
   declaration of conformity, minted as ``doc-N``. Fail-closed: it requires
   a previously booked ``conformant`` assessment for the product; the
   declaration text travels as a digest pin only; one declaration per
   product (a second is refused).
4. ``affix(product_id, seq, mark="ce")`` -- books one marking-affixation
   decision, minted as ``aff-N``, over the pinned mark vocabulary
   (``ce`` / ``ukca`` / ``ce-ukca``). Fail-closed: it requires a booked
   declaration; one affixation per product (a second is refused).

Views (``product_record`` / ``assessments_for`` / ``declared_ids`` /
``affixed_ids`` / ``stats`` / ``audit_log``) are pure reads: seq shape is
validated, never consumed, no audit rows are written.

Distinct-layer rationale: the tree already has ``grc.py`` (governance
workflow ledger), ``compliance.py`` (generic framework check/remediate),
``audit_management.py`` (audit engagement management), and ``iso27001.py``
/ ``soc2.py`` / ``pci_dss.py`` / ``fedramp.py`` / ``cmmc.py`` /
``nist_csf.py`` (standard-specific certification layers). Per the additive
sibling pattern, this module is the *product conformity assessment* layer
none of them owns: it books the product-level DoC and CE-affixation
lifecycle, not an organizational certification.

Honest scope: a booked ``conformant`` verdict means "the host declared this
assessment conformant at this seq", never that the product is conformant.
A booked declaration means "the host declared a DoC", never that a legal
document exists. A booked ``affix`` means "the host declared the marking
affixed", never that a physical marking is present. Declarations are GIGO
host claims.

House style: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn: failed mutations consume their seq and book
``conformity.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only (with the sibling
``canonical_json`` try/except fallback), ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CONFORMITY_VERSION = "conformity.v1"

#: Schema pin carried by records and audit events.
CONFORMITY_SCHEMA = "northstar.conformity.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Declared product-class vocabulary (booked as data).
PRODUCT_CLASSES = (
    "general",
    "machinery",
    "electrical",
    "radio",
    "medical-device",
    "toy",
    "pressure-equipment",
    "construction",
)

#: Declared EU conformity-assessment module vocabulary (booked as data).
ASSESSMENT_MODULES = (
    "a",
    "a1",
    "a2",
    "b",
    "c",
    "c1",
    "c2",
    "d",
    "d1",
    "e",
    "e1",
    "f",
    "f1",
    "g",
    "h",
    "h1",
)

#: Declared assessment-verdict vocabulary (booked as data).
VERDICTS = ("conformant", "non-conformant", "conditional")

#: Declared marking vocabulary (booked as data).
MARKS = ("ce", "ukca", "ce-ukca")

#: Audit kinds for this module (append-only vocabulary).
KIND_PRODUCT_REGISTERED = "conformity.product-registered"
KIND_ASSESSED = "conformity.assessed"
KIND_DECLARED = "conformity.declared"
KIND_AFFIXED = "conformity.affixed"
KIND_REJECTED = "conformity.rejected"
_KINDS = (
    KIND_PRODUCT_REGISTERED,
    KIND_ASSESSED,
    KIND_DECLARED,
    KIND_AFFIXED,
    KIND_REJECTED,
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class ConformityError(Exception):
    """Base class for all conformity ledger failures."""


class BadIdError(ConformityError):
    """Product or record id is malformed."""


class DuplicateProductError(ConformityError):
    """A product id is already booked."""


class UnknownProductError(ConformityError):
    """No product is booked under this id."""


class BadDigestError(ConformityError):
    """A digest pin is not a valid sha256: pin (or empty)."""


class BadClassError(ConformityError):
    """Product class is not in the pinned vocabulary."""


class BadModuleError(ConformityError):
    """Assessment module is not in the pinned vocabulary."""


class BadVerdictError(ConformityError):
    """Verdict is not in the pinned vocabulary."""


class BadMarkError(ConformityError):
    """Mark is not in the pinned vocabulary."""


class UnknownAssessmentError(ConformityError):
    """No assessment is booked under this id."""


class NotConformantError(ConformityError):
    """A declaration requires a booked conformant assessment."""


class AlreadyDeclaredError(ConformityError):
    """A product that already has a declaration cannot be declared again."""


class NotDeclaredError(ConformityError):
    """Affixation requires a booked declaration."""


class AlreadyAffixedError(ConformityError):
    """A product that already has an affixation cannot be affixed again."""


class SeqOrderError(ConformityError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(ConformityError):
    """Unknown audit kind or banned key in audit detail."""


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str = "product_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadIdError(f"{name} must not contain whitespace")
    return value


def _check_optional_digest(value: Any, name: str) -> str:
    """Digest pin or '' (content pins never required at declaration time)."""
    if value == "":
        return ""
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    try:
        int(value[len("sha256:"):], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    return value


def _check_product_class(value: Any) -> str:
    if not isinstance(value, str) or value not in PRODUCT_CLASSES:
        raise BadClassError(f"product_class must be one of {PRODUCT_CLASSES}")
    return value


def _check_module(value: Any) -> str:
    if not isinstance(value, str) or value not in ASSESSMENT_MODULES:
        raise BadModuleError(f"module must be one of {ASSESSMENT_MODULES}")
    return value


def _check_verdict(value: Any) -> str:
    if not isinstance(value, str) or value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_mark(value: Any) -> str:
    if not isinstance(value, str) or value not in MARKS:
        raise BadMarkError(f"mark must be one of {MARKS}")
    return value


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        try:
            return _cj.jcs_dumps(obj).encode("utf-8")
        except Exception:
            pass
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.conformity:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def conformity_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw declaration material never crosses this boundary."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "declaration",
        "product",
        "description",
        "serial",
        "notified-body",
        "notified_body",
        "report",
        "certificate",
        "text",
        "content",
        "payload",
        "notes",
        "raw",
        "secret",
        "private",
        "evidence",
        "model",
        "name",
    )
    for key in detail:
        if key in banned:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    event = {
        "schema": AUDIT_SCHEMA,
        "module": CONFORMITY_SCHEMA,
        "kind": audit_kind,
        "seq": _check_seq(seq),
        "detail": dict(detail),
    }
    return event


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProductRecord:
    """One registered product."""

    product_id: str
    product_class: str
    product_digest: str
    seq: int
    digest: str
    schema: str = CONFORMITY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.product_id,
                self.product_class,
                self.product_digest,
                self.seq,
            ),
            "product",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": CONFORMITY_VERSION,
            "product_id": self.product_id,
            "product_class": self.product_class,
            "product_digest": self.product_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared conformity assessment (minted asm-N)."""

    assessment_id: str
    product_id: str
    module: str
    verdict: str
    standard_digest: str
    seq: int
    digest: str
    schema: str = CONFORMITY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.assessment_id,
                self.product_id,
                self.module,
                self.verdict,
                self.standard_digest,
                self.seq,
            ),
            "assessment",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": CONFORMITY_VERSION,
            "assessment_id": self.assessment_id,
            "product_id": self.product_id,
            "module": self.module,
            "verdict": self.verdict,
            "standard_digest": self.standard_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DeclarationRecord:
    """One booked EU declaration of conformity (minted doc-N)."""

    declaration_id: str
    product_id: str
    declaration_digest: str
    seq: int
    digest: str
    schema: str = CONFORMITY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.declaration_id,
                self.product_id,
                self.declaration_digest,
                self.seq,
            ),
            "declaration",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": CONFORMITY_VERSION,
            "declaration_id": self.declaration_id,
            "product_id": self.product_id,
            "declaration_digest": self.declaration_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AffixRecord:
    """One booked marking-affixation decision (minted aff-N)."""

    affix_id: str
    product_id: str
    mark: str
    seq: int
    digest: str
    schema: str = CONFORMITY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.affix_id,
                self.product_id,
                self.mark,
                self.seq,
            ),
            "affix",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": CONFORMITY_VERSION,
            "affix_id": self.affix_id,
            "product_id": self.product_id,
            "mark": self.mark,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class Conformity:
    """Conformity-assessment decision ledger: register -> assess -> declare -> affix."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._products: Dict[str, ProductRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_for: Dict[str, List[str]] = {}
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._declarations_for: Dict[str, str] = {}
        self._affixes: Dict[str, AffixRecord] = {}
        self._affixes_for: Dict[str, str] = {}
        self._asm_counter = 0
        self._doc_counter = 0
        self._aff_counter = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}"
            )
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: ConformityError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            conformity_audit_event(
                KIND_REJECTED,
                seq_v,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _emit(self, audit_kind: str, seq_v: int, **detail: Any) -> None:
        self._audit.append(conformity_audit_event(audit_kind, seq_v, **detail))

    # -- mutations --------------------------------------------------------

    def register_product(
        self,
        product_id: Any,
        seq: Any,
        product_class: Any = "general",
        product_digest: Any = "",
    ) -> ProductRecord:
        """Book one product into the ledger."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(product_id)
                if pid in self._products:
                    raise DuplicateProductError(f"product already registered: {pid!r}")
                pclass = _check_product_class(product_class)
                pin = _check_optional_digest(product_digest, "product_digest")
                rec = ProductRecord(
                    product_id=pid,
                    product_class=pclass,
                    product_digest=pin,
                    seq=seq_v,
                    digest=_digest_pin((pid, pclass, pin, seq_v), "product"),
                )
                self._products[pid] = rec
                self._emit(
                    KIND_PRODUCT_REGISTERED,
                    seq_v,
                    product_id=pid,
                    product_class=pclass,
                )
                return rec
            except ConformityError as exc:
                self._burn(seq_v, "register_product", exc)
                raise

    def assess(
        self,
        product_id: Any,
        seq: Any,
        module: Any = "a",
        verdict: Any = "conformant",
        standard_digest: Any = "",
    ) -> AssessmentRecord:
        """Book one declared conformity assessment (minted asm-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(product_id)
                if pid not in self._products:
                    raise UnknownProductError(f"unknown product: {pid!r}")
                mod = _check_module(module)
                vdt = _check_verdict(verdict)
                pin = _check_optional_digest(standard_digest, "standard_digest")
                self._asm_counter += 1
                asm_id = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=asm_id,
                    product_id=pid,
                    module=mod,
                    verdict=vdt,
                    standard_digest=pin,
                    seq=seq_v,
                    digest=_digest_pin(
                        (asm_id, pid, mod, vdt, pin, seq_v), "assessment"
                    ),
                )
                self._assessments[asm_id] = rec
                self._assessments_for.setdefault(pid, []).append(asm_id)
                self._emit(
                    KIND_ASSESSED,
                    seq_v,
                    assessment_id=asm_id,
                    product_id=pid,
                    module=mod,
                    verdict=vdt,
                )
                return rec
            except ConformityError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def declare(
        self,
        product_id: Any,
        seq: Any,
        declaration_digest: Any = "",
    ) -> DeclarationRecord:
        """Book one EU declaration of conformity (minted doc-N).

        Fail-closed: requires a previously booked ``conformant`` assessment
        for the product; one declaration per product.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(product_id)
                if pid not in self._products:
                    raise UnknownProductError(f"unknown product: {pid!r}")
                if pid in self._declarations_for:
                    raise AlreadyDeclaredError(
                        f"product already declared: {pid!r}"
                    )
                if not any(
                    self._assessments[a].verdict == "conformant"
                    for a in self._assessments_for.get(pid, ())
                ):
                    raise NotConformantError(
                        f"no booked conformant assessment for {pid!r}"
                    )
                pin = _check_optional_digest(declaration_digest, "declaration_digest")
                self._doc_counter += 1
                doc_id = f"doc-{self._doc_counter}"
                rec = DeclarationRecord(
                    declaration_id=doc_id,
                    product_id=pid,
                    declaration_digest=pin,
                    seq=seq_v,
                    digest=_digest_pin((doc_id, pid, pin, seq_v), "declaration"),
                )
                self._declarations[doc_id] = rec
                self._declarations_for[pid] = doc_id
                self._emit(
                    KIND_DECLARED,
                    seq_v,
                    declaration_id=doc_id,
                    product_id=pid,
                )
                return rec
            except ConformityError as exc:
                self._burn(seq_v, "declare", exc)
                raise

    def affix(
        self,
        product_id: Any,
        seq: Any,
        mark: Any = "ce",
    ) -> AffixRecord:
        """Book one marking-affixation decision (minted aff-N).

        Fail-closed: requires a booked declaration for the product; one
        affixation per product.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                pid = _check_id(product_id)
                if pid not in self._products:
                    raise UnknownProductError(f"unknown product: {pid!r}")
                if pid not in self._declarations_for:
                    raise NotDeclaredError(
                        f"no booked declaration for {pid!r}"
                    )
                if pid in self._affixes_for:
                    raise AlreadyAffixedError(
                        f"product already affixed: {pid!r}"
                    )
                m = _check_mark(mark)
                self._aff_counter += 1
                aff_id = f"aff-{self._aff_counter}"
                rec = AffixRecord(
                    affix_id=aff_id,
                    product_id=pid,
                    mark=m,
                    seq=seq_v,
                    digest=_digest_pin((aff_id, pid, m, seq_v), "affix"),
                )
                self._affixes[aff_id] = rec
                self._affixes_for[pid] = aff_id
                self._emit(
                    KIND_AFFIXED,
                    seq_v,
                    affix_id=aff_id,
                    product_id=pid,
                    mark=m,
                )
                return rec
            except ConformityError as exc:
                self._burn(seq_v, "affix", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def product_record(self, product_id: Any, seq: Any) -> ProductRecord:
        """Return one product record (pure read)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(product_id)
            if pid not in self._products:
                raise UnknownProductError(f"unknown product: {pid!r}")
            return self._products[pid]

    def assessment_record(self, assessment_id: Any, seq: Any) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def declaration_record(self, declaration_id: Any, seq: Any) -> DeclarationRecord:
        """Return one declaration record (pure read)."""
        with self._lock:
            _check_seq(seq)
            did = _check_id(declaration_id, "declaration_id")
            if did not in self._declarations:
                raise UnknownAssessmentError(f"unknown declaration: {did!r}")
            return self._declarations[did]

    def affix_record(self, affix_id: Any, seq: Any) -> AffixRecord:
        """Return one affix record (pure read)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(affix_id, "affix_id")
            if aid not in self._affixes:
                raise UnknownAssessmentError(f"unknown affix: {aid!r}")
            return self._affixes[aid]

    def product_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered product ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._products.keys())

    def assessments_for(self, product_id: Any, seq: Any) -> Tuple[str, ...]:
        """Assessment ids booked against one product (mint order)."""
        with self._lock:
            _check_seq(seq)
            pid = _check_id(product_id)
            if pid not in self._products:
                raise UnknownProductError(f"unknown product: {pid!r}")
            return tuple(self._assessments_for.get(pid, ()))

    def declared_ids(self, seq: Any) -> Tuple[str, ...]:
        """Product ids that carry a declaration."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._declarations_for.keys())

    def affixed_ids(self, seq: Any) -> Tuple[str, ...]:
        """Product ids that carry an affixation."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._affixes_for.keys())

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "products": len(self._products),
                "assessments": len(self._assessments),
                "declarations": len(self._declarations),
                "affixes": len(self._affixes),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    c = Conformity()
    c.register_product("p1", 1, product_class="electrical")
    c.assess("p1", 2, module="b", verdict="conformant")
    c.assess("p1", 3, module="c", verdict="conformant")
    d = c.declare("p1", 4)
    assert d.declaration_id == "doc-1"
    a = c.affix("p1", 5, mark="ce")
    assert a.affix_id == "aff-1"
    assert a.verify()
    assert d.verify()
    assert c.stats(6) == {
        "products": 1,
        "assessments": 2,
        "declarations": 1,
        "affixes": 1,
        "rejected": 0,
    }
    print("conformity OK: register, assess, declare, affix, pins, audit")


if __name__ == "__main__":
    main()
