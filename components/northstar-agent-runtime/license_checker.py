"""License compatibility checker: SPDX expressions, policy gates, compat matrix.

Research motivation: agent systems assemble software from components that
carry different licenses — a runtime that vendors, generates, or remixes
code must answer "can I combine / distribute this?" deterministically,
without phoning home. This module is the *bookkeeping* half of that
answer:

* **Policy gate** (``check``) — a pinned SPDX license expression is
  validated fail-closed against the SPDX License List subset, reduced to
  a copyleft class (permissive / weak-copyleft / strong-copyleft /
  network-copyleft), and judged against a named policy
  (``"permissive-only"``, ``"weak-ok"``, ``"copyleft-ok"``,
  ``"network-ok"``). Verdicts are *data*, never exceptions — the host's
  release pipeline decides what "denied" does.
* **Compatibility** (``compat``) — two SPDX expressions are assessed
  pairwise: same-id, permissive subsumption, and a pinned table of the
  famous incompatibilities (GPLv2-only vs Apache-2.0, GPLv2 vs GPLv3,
  CDDL vs GPL, EPL-1.0 vs GPL, MPL-2.0 vs GPL-2.0-only, EPL-2.0 vs
  GPL-2.0-only, CC-BY-SA-4.0 vs GPL-2.0-only). The combined work's
  effective copyleft level is reported so the caller knows the terms
  the combination inherits.
* **Audit** (``audit``) — a frozen, digest-pinned ledger summary of
  every check and assessment performed: verdict histogram, record ids,
  pins.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
(hashlib, re, threading, dataclasses, typing), type-tagged canonical
digest pins (the batch-5 JCS discipline), ``audit.ndjson/1`` events,
``main()`` self-check.

Honest scope: this pins *host-reported* license expressions and applies
a curated subset of the SPDX list plus a curated conflict table. It
cannot read the actual license text, prove the expression is truthful,
or adjudicate the law — legal conclusions are outside the interface. A
"compatible" verdict means "no *known* conflict in the pinned table",
never "a lawyer approves". Verdicts are bookkeeping; the host owns the
release decision (GIGO boundary).
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
LICENSE_CHECKER_VERSION = "license-checker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.license-checker.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "license-checked",
    "compat-assessed",
    "audited",
    "rejected",
)

#: Pinned subset of the SPDX License List (same curated subset as
#: ``sbom_generator`` — identifiers exactly as the SPDX list publishes
#: them). The fail-closed discipline (unknown tokens refused) is the
#: point, not exhaustive coverage.
SPDX_LICENSE_IDS = frozenset({
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "CDDL-1.0",
    "CC0-1.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
    "Unlicense",
    "BSL-1.0",
    "Zlib",
    "Python-2.0",
    "Artistic-2.0",
    "PSF-2.0",
    "OSL-3.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "NOASSERTION",
    "NONE",
})

#: Copyleft classes: 0 = permissive / public-domain, 1 = weak copyleft,
#: 2 = strong copyleft, 3 = network copyleft. Curated from SPDX/FSF
#: guidance. Not a legal taxonomy — a bookkeeping ordering.
_LICENSE_CLASSES = {
    # level 0 — permissive / public-domain
    "MIT": 0, "Apache-2.0": 0, "BSD-2-Clause": 0, "BSD-3-Clause": 0,
    "ISC": 0, "CC0-1.0": 0, "Unlicense": 0, "Zlib": 0, "BSL-1.0": 0,
    "Python-2.0": 0, "PSF-2.0": 0, "Artistic-2.0": 0, "CC-BY-4.0": 0,
    # level 1 — weak copyleft (file/module scope)
    "LGPL-2.0-only": 1, "LGPL-2.0-or-later": 1, "LGPL-2.1-only": 1,
    "LGPL-2.1-or-later": 1, "LGPL-3.0-only": 1, "LGPL-3.0-or-later": 1,
    "MPL-2.0": 1, "EPL-1.0": 1, "EPL-2.0": 1, "CDDL-1.0": 1,
    "EUPL-1.1": 1, "EUPL-1.2": 1, "CC-BY-SA-4.0": 1,
    # level 2 — strong copyleft (work scope)
    "GPL-2.0-only": 2, "GPL-2.0-or-later": 2, "GPL-3.0-only": 2,
    "GPL-3.0-or-later": 2, "OSL-3.0": 2,
    # level 3 — network copyleft
    "AGPL-3.0-only": 3, "AGPL-3.0-or-later": 3,
}

_LEVEL_NAMES = {
    0: "permissive",
    1: "weak-copyleft",
    2: "strong-copyleft",
    3: "network-copyleft",
}

#: Pinned policy names: the maximum copyleft level the policy admits.
_POLICIES = {
    "permissive-only": 0,
    "weak-ok": 1,
    "copyleft-ok": 2,
    "network-ok": 3,
}

#: Curated conflict table — pairs that are famously incompatible for
#: combined distribution (order-insensitive). Everything else defaults
#: to "compatible" (permissive subsumption), since an exhaustive proof
#: of compatibility is outside the interface.
_INCOMPATIBLE_PAIRS = frozenset({
    frozenset({"GPL-2.0-only", "Apache-2.0"}),
    frozenset({"GPL-2.0-only", "GPL-3.0-only"}),
    frozenset({"GPL-2.0-only", "GPL-3.0-or-later"}),
    frozenset({"GPL-2.0-only", "LGPL-3.0-only"}),
    frozenset({"GPL-2.0-only", "LGPL-3.0-or-later"}),
    frozenset({"GPL-2.0-only", "AGPL-3.0-only"}),
    frozenset({"GPL-2.0-only", "AGPL-3.0-or-later"}),
    frozenset({"GPL-2.0-only", "MPL-2.0"}),
    frozenset({"GPL-2.0-only", "EPL-2.0"}),
    frozenset({"GPL-2.0-only", "EPL-1.0"}),
    frozenset({"GPL-2.0-only", "CC-BY-SA-4.0"}),
    frozenset({"GPL-2.0-only", "CDDL-1.0"}),
    frozenset({"GPL-2.0-or-later", "CDDL-1.0"}),
    frozenset({"GPL-3.0-only", "EPL-1.0"}),
    frozenset({"GPL-3.0-only", "CDDL-1.0"}),
    frozenset({"GPL-3.0-or-later", "EPL-1.0"}),
    frozenset({"GPL-3.0-or-later", "CDDL-1.0"}),
})

#: Ids that are valid SPDX but unclassifiable — verdict "unknown",
#: never guessed.
_UNCLASSIFIABLE = frozenset({"NOASSERTION", "NONE"})

_LICENSEREF_RE = re.compile(r"^LicenseRef-[A-Za-z0-9][A-Za-z0-9.\-+]*$")
_EXPR_OPERATORS = frozenset({"AND", "OR", "WITH"})


class LicenseError(Exception):
    """Base fail-closed license-checker error."""


class UnknownLicenseError(LicenseError):
    """A token is not a pinned SPDX id, LicenseRef-*, NOASSERTION, or NONE."""


class BadExpressionError(LicenseError):
    """The expression does not parse (bad operators, parens, empty)."""


class UnknownPolicyError(LicenseError):
    """The policy name is not one of the pinned policy names."""


class UnknownCheckError(LicenseError):
    """Lookup of an unknown check/report/audit id."""


class SeqOrderError(LicenseError):
    """Seq is not a strictly-increasing non-bool int."""


# ---------------------------------------------------------------------------
# Canonical digest helpers (batch-5 JCS discipline)
# ---------------------------------------------------------------------------

def _canonicalize(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2 ** 53:
            raise LicenseError("integer out of safe JCS range")
        return value
    if isinstance(value, float):
        raise LicenseError("floats refused in canonical encoding")
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    if isinstance(value, (dict,)):
        return {str(k): _canonicalize(value[k]) for k in sorted(value, key=str)}
    raise LicenseError(f"non-canonicalizable value of type {type(value).__name__}")


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(
        jcs_canonical_json(_canonicalize(body))).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be a non-bool int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


# ---------------------------------------------------------------------------
# SPDX expression parsing: OR of ANDs (SPDX Annex D precedence).
# ---------------------------------------------------------------------------

def _tokenize(expr: str) -> List[str]:
    return expr.replace("(", " ( ").replace(")", " ) ").split()


def _parse_expression(expr: str) -> Tuple[Tuple[str, ...], ...]:
    """Parse to a tuple of alternatives; each alternative is a tuple of
    AND-combined license ids. WITH clauses attach to their license token
    (exception recorded, verdict unaffected)."""
    tokens = _tokenize(expr)
    if not tokens:
        raise BadExpressionError("empty license expression")

    pos = 0

    def parse_or() -> Tuple[Tuple[str, ...], ...]:
        nonlocal pos
        alternatives = [parse_and()]
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            alternatives.append(parse_and())
        return tuple(alternatives)

    def parse_and() -> Tuple[str, ...]:
        nonlocal pos
        conjuncts = [parse_primary()]
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            conjuncts.append(parse_primary())
        return tuple(conjuncts)

    def parse_primary() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise BadExpressionError("unexpected end of expression")
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise BadExpressionError("unbalanced parenthesis")
            pos += 1
            if len(inner) != 1:
                raise BadExpressionError("parenthesized OR groups not supported")
            return inner[0][0] if len(inner[0]) == 1 else _unsupported_group(inner)
        if tok in ("AND", "OR", "WITH", ")"):
            raise BadExpressionError(f"unexpected operator {tok!r}")
        pos += 1
        if pos < len(tokens) and tokens[pos] == "WITH":
            pos += 1
            if pos >= len(tokens):
                raise BadExpressionError("WITH without exception name")
            pos += 1  # exception id: recorded implicitly, verdict unaffected
        _validate_token(tok)
        return tok

    alternatives = parse_or()
    if pos != len(tokens):
        raise BadExpressionError(f"trailing tokens at {tokens[pos]!r}")
    return alternatives


def _unsupported_group(inner: Tuple[Tuple[str, ...], ...]) -> str:
    raise BadExpressionError("parenthesized multi-term groups not supported")


def _validate_token(tok: str) -> str:
    if tok in SPDX_LICENSE_IDS or _LICENSEREF_RE.match(tok):
        return tok
    raise UnknownLicenseError(f"not a pinned SPDX id: {tok!r}")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckRecord:
    """One policy-gate decision."""
    check_id: str
    expression: str
    policy: str
    verdict: str            # "allowed" | "denied"
    reason: str
    max_level: int
    level_name: str
    pin: str
    seq: int
    version: str = LICENSE_CHECKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "expression": self.expression,
            "policy": self.policy,
            "verdict": self.verdict,
            "reason": self.reason,
            "max_level": self.max_level,
            "level_name": self.level_name,
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class CompatReport:
    """One pairwise compatibility assessment."""
    report_id: str
    a_expr: str
    b_expr: str
    verdict: str            # "compatible" | "incompatible" | "unknown"
    pair_details: Tuple[Tuple[str, str, str], ...]
    combined_level: int
    combined_ids: Tuple[str, ...]
    pin: str
    seq: int
    version: str = LICENSE_CHECKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "a_expr": self.a_expr,
            "b_expr": self.b_expr,
            "verdict": self.verdict,
            "pair_details": [list(p) for p in self.pair_details],
            "combined_level": self.combined_level,
            "combined_ids": list(self.combined_ids),
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AuditReport:
    """Frozen ledger summary over checks and assessments."""
    audit_id: str
    checks: int
    compat_reports: int
    allowed: int
    denied: int
    compatible: int
    incompatible: int
    unknown: int
    record_ids: Tuple[str, ...]
    pin: str
    seq: int
    version: str = LICENSE_CHECKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "checks": self.checks,
            "compat_reports": self.compat_reports,
            "allowed": self.allowed,
            "denied": self.denied,
            "compatible": self.compatible,
            "incompatible": self.incompatible,
            "unknown": self.unknown,
            "record_ids": list(self.record_ids),
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _class_of(license_id: str) -> Optional[int]:
    """Copyleft level, or None when unclassifiable (LicenseRef-*, etc.)."""
    if license_id in _UNCLASSIFIABLE or _LICENSEREF_RE.match(license_id):
        return None
    return _LICENSE_CLASSES.get(license_id)


def _pair_verdict(a: str, b: str) -> str:
    if a == b:
        return "compatible"
    if a in _UNCLASSIFIABLE or b in _UNCLASSIFIABLE:
        return "unknown"
    if _LICENSEREF_RE.match(a) or _LICENSEREF_RE.match(b):
        return "unknown"
    if frozenset({a, b}) in _INCOMPATIBLE_PAIRS:
        return "incompatible"
    return "compatible"


class LicenseChecker:
    """Policy gate and compatibility matrix for SPDX license expressions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._check_counter = 0
        self._report_counter = 0
        self._audit_counter = 0
        self._checks: Dict[str, CheckRecord] = {}
        self._reports: Dict[str, CompatReport] = {}
        self._audit_log: List[Dict[str, Any]] = []

    # -- internal ---------------------------------------------------------
    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase (last={self._last_seq})")
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(license_checker_audit_event(kind, seq, **detail))

    # -- policy gate -------------------------------------------------------
    def check(self, expression: str, seq: Any,
              policy: str = "copyleft-ok") -> CheckRecord:
        """Gate one SPDX expression against a named policy.

        Dual-licensed (OR) expressions pass when *any* alternative fits
        the policy. Unclassifiable ids (LicenseRef-*, NOASSERTION, NONE)
        are denied fail-closed — a policy cannot admit what it cannot
        name.
        """
        with self._lock:
            seq = _check_seq(seq)
            if not isinstance(expression, str) or not expression.strip():
                raise BadExpressionError("expression must be a non-empty str")
            if policy not in _POLICIES:
                raise UnknownPolicyError(f"unknown policy {policy!r}")
            self._monotonic(seq)
            self._check_counter += 1
            check_id = f"lc-{self._check_counter}"
            try:
                alternatives = _parse_expression(expression)
                limit = _POLICIES[policy]
                best: Optional[Tuple[int, str]] = None
                for alt in alternatives:
                    levels = [_class_of(t) for t in alt]
                    if any(l is None for l in levels):
                        continue  # unclassifiable alternative: cannot pass
                    mx = max(levels)  # type: ignore[arg-type]
                    if mx <= limit and (best is None or mx < best[0]):
                        best = (mx, _LEVEL_NAMES[mx])
                if best is not None:
                    verdict, reason = "allowed", (
                        f"max copyleft level {best[0]} "
                        f"({_LEVEL_NAMES[best[0]]}) within {policy}")
                    max_level = best[0]
                else:
                    verdict, reason = "denied", (
                        "no OR-alternative is classifiable within "
                        f"policy {policy!r}")
                    max_level = -1
                level_name = _LEVEL_NAMES.get(max_level, "unknown")
                pin = _digest({
                    "check_id": check_id, "expression": expression,
                    "policy": policy, "verdict": verdict,
                    "max_level": max_level, "seq": seq,
                    "version": LICENSE_CHECKER_VERSION,
                })
                rec = CheckRecord(
                    check_id=check_id, expression=expression, policy=policy,
                    verdict=verdict, reason=reason, max_level=max_level,
                    level_name=level_name, pin=pin, seq=seq)
                self._checks[check_id] = rec
                self._emit("license-checked", seq, check_id=check_id,
                           verdict=verdict, pin=pin)
                return rec
            except LicenseError as exc:
                self._emit("rejected", seq, operation="check",
                           reason=type(exc).__name__)
                raise

    # -- compatibility ------------------------------------------------------
    def compat(self, a_expr: str, b_expr: str, seq: Any) -> CompatReport:
        """Assess pairwise compatibility of two SPDX expressions.

        Each expression is an OR of alternatives; each alternative is an
        AND-combination. The assessment is compatible when *some*
        (a-alternative, b-alternative) pair has no unknown and no
        conflicted pair; the combined terms inherit the maximum
        copyleft level of that pair.
        """
        with self._lock:
            seq = _check_seq(seq)
            for expr in (a_expr, b_expr):
                if not isinstance(expr, str) or not expr.strip():
                    raise BadExpressionError("expression must be a non-empty str")
            self._monotonic(seq)
            self._report_counter += 1
            report_id = f"lcr-{self._report_counter}"
            try:
                a_alts = _parse_expression(a_expr)
                b_alts = _parse_expression(b_expr)
                details: List[Tuple[str, str, str]] = []
                chosen: Optional[Tuple[FrozenSet[str], int]] = None
                verdict = "incompatible"
                for a_alt in a_alts:
                    for b_alt in b_alts:
                        combined = frozenset(a_alt) | frozenset(b_alt)
                        pair_vs = tuple(
                            (x, y, _pair_verdict(x, y))
                            for x in sorted(a_alt) for y in sorted(b_alt))
                        details.extend(pair_vs)
                        states = {v for _, _, v in pair_vs}
                        if "unknown" in states:
                            if verdict != "compatible":
                                verdict = "unknown"
                        elif "incompatible" not in states:
                            verdict = "compatible"
                            levels = [_class_of(t) for t in combined]
                            if (chosen is None
                                    and all(l is not None for l in levels)):
                                chosen = (combined, max(levels))  # type: ignore[arg-type]
                if chosen is not None:
                    combined_ids = tuple(sorted(chosen[0]))
                    combined_level = chosen[1]
                else:
                    combined_ids = ()
                    combined_level = -1
                pin = _digest({
                    "report_id": report_id, "a_expr": a_expr,
                    "b_expr": b_expr, "verdict": verdict,
                    "details": [list(p) for p in details],
                    "seq": seq, "version": LICENSE_CHECKER_VERSION,
                })
                rep = CompatReport(
                    report_id=report_id, a_expr=a_expr, b_expr=b_expr,
                    verdict=verdict, pair_details=tuple(details),
                    combined_level=combined_level,
                    combined_ids=combined_ids, pin=pin, seq=seq)
                self._reports[report_id] = rep
                self._emit("compat-assessed", seq, report_id=report_id,
                           verdict=verdict, pin=pin)
                return rep
            except LicenseError as exc:
                self._emit("rejected", seq, operation="compat",
                           reason=type(exc).__name__)
                raise

    # -- audit ---------------------------------------------------------------
    def audit(self, seq: Any) -> AuditReport:
        """Frozen, digest-pinned summary of every check and assessment."""
        with self._lock:
            seq = _check_seq(seq)
            self._monotonic(seq)
            self._audit_counter += 1
            audit_id = f"ar-{self._audit_counter}"
            checks = tuple(self._checks.values())
            reports = tuple(self._reports.values())
            allowed = sum(1 for c in checks if c.verdict == "allowed")
            compatible = sum(1 for r in reports if r.verdict == "compatible")
            incompatible = sum(1 for r in reports if r.verdict == "incompatible")
            unknown = sum(1 for r in reports if r.verdict == "unknown")
            record_ids = tuple(
                sorted([c.check_id for c in checks]
                       + [r.report_id for r in reports]))
            pin = _digest({
                "audit_id": audit_id, "checks": len(checks),
                "compat_reports": len(reports), "allowed": allowed,
                "denied": len(checks) - allowed, "compatible": compatible,
                "incompatible": incompatible, "unknown": unknown,
                "record_ids": list(record_ids), "seq": seq,
                "version": LICENSE_CHECKER_VERSION,
            })
            rep = AuditReport(
                audit_id=audit_id, checks=len(checks),
                compat_reports=len(reports), allowed=allowed,
                denied=len(checks) - allowed, compatible=compatible,
                incompatible=incompatible, unknown=unknown,
                record_ids=record_ids, pin=pin, seq=seq)
            self._emit("audited", seq, audit_id=audit_id, pin=pin)
            return rep

    # -- views ---------------------------------------------------------------
    def check_record(self, check_id: str) -> CheckRecord:
        with self._lock:
            try:
                return self._checks[check_id]
            except KeyError:
                raise UnknownCheckError(f"unknown check {check_id!r}")

    def compat_report(self, report_id: str) -> CompatReport:
        with self._lock:
            try:
                return self._reports[report_id]
            except KeyError:
                raise UnknownCheckError(f"unknown report {report_id!r}")

    def check_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._checks)

    def report_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._reports)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def license_checker_audit_event(kind: str, seq: int,
                                **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for license-checker activity."""
    if kind not in _AUDIT_KINDS:
        raise LicenseError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": LICENSE_CHECKER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    event.update({k: _canonicalize(v) for k, v in detail.items()})
    return event


def main() -> None:
    """Self-check: policy gate, dual-license OR, conflict table, audit."""
    lc = LicenseChecker()
    r1 = lc.check("MIT", 0)
    assert r1.verdict == "allowed" and r1.max_level == 0, r1.as_dict()
    assert r1.pin.startswith("sha256:")
    r2 = lc.check("GPL-3.0-only", 1, policy="permissive-only")
    assert r2.verdict == "denied", r2.as_dict()
    r3 = lc.check("GPL-3.0-only OR MIT", 2, policy="permissive-only")
    assert r3.verdict == "allowed", r3.as_dict()
    r4 = lc.check("LicenseRef-Foo", 3)
    assert r4.verdict == "denied", r4.as_dict()
    c1 = lc.compat("MIT", "GPL-3.0-only", 4)
    assert c1.verdict == "compatible" and c1.combined_level == 2, c1.as_dict()
    c2 = lc.compat("GPL-2.0-only", "Apache-2.0", 5)
    assert c2.verdict == "incompatible", c2.as_dict()
    c3 = lc.compat("GPL-2.0-only", "GPL-3.0-only", 6)
    assert c3.verdict == "incompatible", c3.as_dict()
    c4 = lc.compat("LicenseRef-Bar", "MIT", 7)
    assert c4.verdict == "unknown", c4.as_dict()
    a = lc.audit(8)
    assert a.checks == 4 and a.compat_reports == 4, a.as_dict()
    assert a.allowed == 2 and a.denied == 2
    assert a.compatible == 1 and a.incompatible == 2 and a.unknown == 1
    assert a.pin.startswith("sha256:")
    print("license-checker OK: check, dual-license, conflict table, audit")


if __name__ == "__main__":
    main()
