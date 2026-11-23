"""Version manager: semantic version parsing, comparison, and range checks.

Research note: semantic versioning (semver.org, the npm/cargo/maven lingua
franca) encodes compatibility intent in three numbers plus optional
pre-release/build metadata: ``MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]``.
The load-bearing rules are: (1) *precedence* — numeric fields compare
numerically, pre-releases compare by dot-separated identifiers (numeric
identifiers compare numerically, alphanumeric lexically, numeric has lower
precedence than alphanumeric), and a version *with* a pre-release has lower
precedence than the same version without one; (2) *equality ignores build
metadata* — ``1.2.3+build.5`` == ``1.2.3+build.9``; (3) *ranges* —
``^1.2.3`` (compatible), ``~1.2.3`` (approximately equivalent), ``>=`` /
``<=`` / ``>`` / ``<`` / ``=`` comparators, hyphen ranges, ``*`` wildcards,
and compound ``||`` unions let dependency solvers express "which versions
am I willing to accept".

This module implements that shape as a deterministic, single-host
bookkeeping service:

* **Parsing** — :meth:`VersionManager.parse` admits a version string to the
  registry as a frozen :class:`VersionRecord` with a ``sha256:`` digest pin
  over the canonical tuple. Strict mode admits only full ``X.Y.Z`` triples
  (semver org discipline); loose mode also admits ``X.Y`` and ``X``
  (maven/npm shorthand), padding the missing fields with zeros.
* **Comparison** — :meth:`VersionManager.compare` returns ``-1``/``0``/``1``
  under the semver 2.0.0 precedence rules. Numeric prerelease identifiers
  compare numerically, alphanumeric lexically; numeric < alphanumeric; a
  longer prerelease field list wins when all preceding identifiers are
  equal; build metadata never affects precedence (or digest equality).
* **Ranges** — :meth:`VersionManager.satisfies` evaluates a version against
  an npm-style range string: comparators, caret/tilde, ``x``/``*``
  wildcards, hyphen ranges, and ``||`` unions. Pre-release versions only
  satisfy a range when the range mentions a pre-release on the same
  ``MAJOR.MINOR.PATCH`` (npm "desugared pre-release" discipline).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per manager, no wall-clock, no RNG), RLock-guarded, fail-closed
(empty strings, malformed versions, negative seqs, unknown range syntax
all raise a subclass of :class:`VersionError`), stdlib-only, type-tagged
canonical digest encoding (bool ≠ int; NaN/inf refused — there is no
floating point in this module at all), audit events shaped for
``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a registry or solver. It pins
what the host *reported*; a host that lies gets a consistent ledger of
lies (GIGO, same boundary as every other bookkeeping module). ``satisfies``
evaluates one candidate version against one range — it never fetches,
resolves, or selects among candidates.

Version pin: version-manager.v1
Schema pin: northstar.version-manager.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version pin.
VERSION_MANAGER_VERSION = "version-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.version-manager.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds this module emits.
KIND_PARSED = "parsed"
KIND_COMPARED = "compared"
KIND_SATISFIED = "satisfied"
KIND_REJECTED = "rejected"
AUDIT_KINDS = (KIND_PARSED, KIND_COMPARED, KIND_SATISFIED, KIND_REJECTED)


class VersionError(ValueError):
    """Base fail-closed version-manager error."""


class BadVersionError(VersionError):
    """The version string is not a valid (strict or loose) semver."""


class DuplicateVersionError(VersionError):
    """The canonical version string is already registered."""


class UnknownVersionError(VersionError):
    """No registered record for this version id."""


class BadRangeError(VersionError):
    """The range string is not a valid range expression."""


class SeqOrderError(VersionError):
    """A caller-supplied seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Small validators
# ---------------------------------------------------------------------------

def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise VersionError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise VersionError(f"{what} must be a non-empty str")
    return value


def _digest(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(dict(body))).hexdigest()


# ---------------------------------------------------------------------------
# Semver grammar
# ---------------------------------------------------------------------------

#: A numeric identifier: no leading zeros unless the value is zero itself.
_NUMERIC = r"(?:0|[1-9]\d*)"
#: An alphanumeric identifier: ASCII alphanumerics plus hyphen, must contain
#: a non-digit to distinguish it from a numeric identifier.
_ALNUM = r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
_STRICT_RE = re.compile(
    rf"^({_NUMERIC})\.({_NUMERIC})\.({_NUMERIC})"
    rf"(?:-({_ALNUM}|{_NUMERIC})(?:\.({_ALNUM}|{_NUMERIC}))*?)?"
    rf"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_LOOSE_RE = re.compile(
    rf"^({_NUMERIC})(?:\.({_NUMERIC})(?:\.({_NUMERIC}))?)?"
    rf"(?:-({_ALNUM}|{_NUMERIC})(?:\.({_ALNUM}|{_NUMERIC}))*?)?"
    rf"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _split_identifiers(text: Optional[str]) -> Tuple[str, ...]:
    if text is None:
        return ()
    return tuple(text.split("."))


def _ident_key(ident: str) -> Tuple[int, Any]:
    # Numeric identifiers (no leading zeros guaranteed by the grammar)
    # sort below alphanumeric identifiers and compare numerically.
    if ident.isdigit():
        return (0, int(ident))
    return (1, ident)


@dataclass(frozen=True)
class VersionRecord:
    """One registered, digest-pinned version."""

    version_id: str
    original: str
    major: int
    minor: int
    patch: int
    prerelease: Tuple[str, ...]
    build: Tuple[str, ...]
    canonical: str
    digest: str
    seq: int
    version: str = VERSION_MANAGER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "original": self.original,
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": list(self.prerelease),
            "build": list(self.build),
            "canonical": self.canonical,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin from the record's contents."""
        body = {
            "canonical": self.canonical,
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": list(self.prerelease),
            "build": list(self.build),
            "version_id": self.version_id,
        }
        return _digest(body) == self.digest


@dataclass(frozen=True)
class ComparisonReport:
    """Result of one compare() call."""

    left_id: str
    right_id: str
    result: int  # -1, 0, or 1
    left_canonical: str
    right_canonical: str
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "result": self.result,
            "left_canonical": self.left_canonical,
            "right_canonical": self.right_canonical,
            "digest": self.digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class RangeReport:
    """Result of one satisfies() call."""

    version_id: str
    version_canonical: str
    range_text: str
    satisfies: bool
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "version_canonical": self.version_canonical,
            "range_text": self.range_text,
            "satisfies": self.satisfies,
            "digest": self.digest,
            "seq": self.seq,
        }


# ---------------------------------------------------------------------------
# Range AST
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Comparator:
    op: str  # one of <, <=, >, >=, =
    major: int
    minor: int
    patch: int
    prerelease: Tuple[str, ...]


@dataclass(frozen=True)
class _RangeSet:
    comparators: Tuple[_Comparator, ...]


@dataclass(frozen=True)
class _Range:
    sets: Tuple[_RangeSet, ...]


def _parse_version_tuple(major: int, minor: int, patch: int,
                         prerelease: Tuple[str, ...]) -> Tuple[int, int, int, Tuple[str, ...]]:
    return (major, minor, patch, prerelease)


def _compare_pre(pr_a: Tuple[str, ...], pr_b: Tuple[str, ...]) -> int:
    # A version without a prerelease has HIGHER precedence than one with.
    if not pr_a and not pr_b:
        return 0
    if not pr_a:
        return 1
    if not pr_b:
        return -1
    for a, b in zip(pr_a, pr_b):
        ka, kb = _ident_key(a), _ident_key(b)
        if ka != kb:
            return -1 if ka < kb else 1
    if len(pr_a) == len(pr_b):
        return 0
    # Larger set of identifiers wins when all preceding are equal.
    return 1 if len(pr_a) > len(pr_b) else -1


def _compare_versions(left: Tuple[int, int, int, Tuple[str, ...]],
                      right: Tuple[int, int, int, Tuple[str, ...]]) -> int:
    for a, b in zip(left[:3], right[:3]):
        if a != b:
            return -1 if a < b else 1
    return _compare_pre(left[3], right[3])


class _RangeParser:
    """npm-style range parser producing a _Range AST."""

    _OP_RE = re.compile(r"^(<=|>=|<|>|=|==)?\s*(.+?)\s*$")

    def __init__(self, text: str) -> None:
        self.text = text

    # -- entry ------------------------------------------------------------
    def parse(self) -> _Range:
        _check_str(self.text, "range")
        raw = self.text.strip()
        if raw in ("", "*", "x", "X"):
            return _Range(sets=(_RangeSet(comparators=()),))
        sets: List[_RangeSet] = []
        for part in re.split(r"\s*\|\|\s*", raw):
            part = part.strip()
            if not part:
                raise BadRangeError(f"empty range set in {self.text!r}")
            sets.append(self._parse_set(part))
        if not sets:
            raise BadRangeError(f"empty range {self.text!r}")
        return _Range(sets=tuple(sets))

    # -- one || branch ----------------------------------------------------
    def _parse_set(self, text: str) -> _RangeSet:
        # Hyphen ranges: "1.2.3 - 2.3.4" (with optional prerelease/build).
        hyphen = re.match(
            r"^\s*(\S+)\s+-\s+(\S+)\s*$", text)
        if hyphen:
            lo = self._full_version(hyphen.group(1))
            hi = self._full_version(hyphen.group(2))
            return _RangeSet(comparators=(
                _Comparator(">=", *lo),
                _Comparator("<=", *hi),
            ))
        comparators: List[_Comparator] = []
        for token in text.split():
            comparators.extend(self._parse_token(token))
        return _RangeSet(comparators=tuple(comparators))

    def _parse_token(self, token: str) -> List[_Comparator]:
        m = self._OP_RE.match(token)
        if not m:
            raise BadRangeError(f"bad range token {token!r}")
        op = m.group(1) or ""
        rest = m.group(2)
        if op == "==":
            op = "="
        # Caret/tilde come through as a prefix on `rest` because the op
        # regex above only knows the relational operators.
        prefix = ""
        if rest[:1] in ("^", "~"):
            prefix, rest = rest[0], rest[1:]
        # Wildcards: 1.x, 1.*, 1.2.x, x, *
        if re.fullmatch(r"(?i)(x|\*)", rest) or re.fullmatch(
                r"(?i)(\d+)\.(x|\*)", rest) or re.fullmatch(
                r"(?i)(\d+)\.(\d+)\.(x|\*)", rest):
            parts = re.split(r"\.", rest)
            nums = [p for p in parts if p not in ("x", "X", "*")]
            if not nums:
                return []  # bare x/* matches everything
            major = int(nums[0])
            minor = int(nums[1]) if len(nums) > 1 else None
            patch = int(nums[2]) if len(nums) > 2 else None
            out: List[_Comparator] = [
                _Comparator(">=", major,
                            minor if minor is not None else 0,
                            patch if patch is not None else 0, ()),
            ]
            if minor is None:
                out.append(_Comparator("<", major + 1, 0, 0, ()))
            elif patch is None:
                out.append(_Comparator("<", major, minor + 1, 0, ()))
            return out
        if op == "^" or prefix == "^":
            major, minor, patch, pre, _depth = self._partial_version(rest)
            upper: Tuple[int, int, int]
            if major > 0:
                upper = (major + 1, 0, 0)
            elif minor > 0:
                upper = (0, minor + 1, 0)
            else:
                upper = (0, 0, patch + 1)
            return [
                _Comparator(">=", major, minor, patch, pre),
                _Comparator("<", upper[0], upper[1], upper[2], ()),
            ]
        if op == "~" or prefix == "~":
            major, minor, patch, pre, depth = self._partial_version(rest)
            # ~1.2.3 := >=1.2.3 <1.3.0 ; ~1.2 := >=1.2.0 <1.3.0 ; ~1 := >=1.0.0 <2.0.0
            upper = (major + 1, 0, 0) if depth == 1 else (major, minor + 1, 0)
            return [
                _Comparator(">=", major, minor, patch, pre),
                _Comparator("<", upper[0], upper[1], upper[2], ()),
            ]
        major, minor, patch, pre = self._full_version(rest)
        return [_Comparator(op or "=", major, minor, patch, pre)]

    @staticmethod
    def _full_version(text: str) -> Tuple[int, int, int, Tuple[str, ...]]:
        m = _STRICT_RE.match(text.strip())
        if not m:
            raise BadRangeError(f"range version {text!r} is not strict X.Y.Z")
        return _RangeParser._ident_tuple(m, text.strip())

    @staticmethod
    def _ident_tuple(m: "re.Match[str]", text: str) -> Tuple[int, int, int, Tuple[str, ...]]:
        dash = text.find("-")
        plus = text.find("+")
        pre: Tuple[str, ...] = ()
        if dash != -1:
            end = plus if plus != -1 else len(text)
            pre = tuple(text[dash + 1:end].split("."))
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)

    @staticmethod
    def _partial_version(text: str) -> Tuple[int, int, int, Tuple[str, ...], int]:
        """Parse X[.Y[.Z]][-pre][+build]; returns (major, minor, patch, pre, depth)."""
        text = text.strip()
        m = _LOOSE_RE.match(text)
        if not m:
            raise BadRangeError(f"range version {text!r} is not a version")
        dash = text.find("-")
        plus = text.find("+")
        pre: Tuple[str, ...] = ()
        if dash != -1:
            end = plus if plus != -1 else len(text)
            pre = tuple(text[dash + 1:end].split("."))
        major = int(m.group(1))
        minor = int(m.group(2)) if m.group(2) is not None else 0
        patch = int(m.group(3)) if m.group(3) is not None else 0
        depth = 3 if m.group(3) is not None else (2 if m.group(2) is not None else 1)
        return (major, minor, patch, pre, depth)


def _eval_comparator(cmp: _Comparator,
                     version: Tuple[int, int, int, Tuple[str, ...]]) -> bool:
    target = _parse_version_tuple(cmp.major, cmp.minor, cmp.patch, cmp.prerelease)
    result = _compare_versions(version, target)
    op = cmp.op
    if op == "=":
        return result == 0
    if op == "<":
        return result == -1
    if op == "<=":
        return result in (-1, 0)
    if op == ">":
        return result == 1
    if op == ">=":
        return result in (0, 1)
    raise BadRangeError(f"unknown comparator op {op!r}")


def _eval_range(rng: _Range,
                version: Tuple[int, int, int, Tuple[str, ...]]) -> bool:
    has_pre = bool(version[3])
    for rset in rng.sets:
        # npm pre-release discipline: a pre-release version only satisfies a
        # set that mentions a pre-release on the same MAJOR.MINOR.PATCH.
        if has_pre and not any(
                c.prerelease and (c.major, c.minor, c.patch) == version[:3]
                for c in rset.comparators):
            continue
        if all(_eval_comparator(c, version) for c in rset.comparators):
            return True
    return False


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class VersionManager:
    """Registry of digest-pinned versions with compare and range checks."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, VersionRecord] = {}
        self._by_canonical: Dict[str, str] = {}
        self._counter = 0
        self._last_seq = -1

    def _monotonic(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    @staticmethod
    def _canonical(major: int, minor: int, patch: int,
                   prerelease: Tuple[str, ...],
                   build: Tuple[str, ...]) -> str:
        text = f"{major}.{minor}.{patch}"
        if prerelease:
            text += "-" + ".".join(prerelease)
        if build:
            text += "+" + ".".join(build)
        return text

    def parse(self, text: str, seq: int, *, strict: bool = True) -> VersionRecord:
        """Admit a version string; returns its pinned record.

        Strict mode requires a full ``X.Y.Z`` triple (leading zeros
        refused); loose mode pads ``X`` / ``X.Y`` with zeros.
        """
        with self._lock:
            seq = self._monotonic(seq)
            _check_str(text, "version")
            text = text.strip()
            m = (_STRICT_RE if strict else _LOOSE_RE).match(text)
            if not m:
                raise BadVersionError(
                    f"not a {'strict' if strict else 'loose'} semver: {text!r}")
            major = int(m.group(1))
            minor = int(m.group(2)) if m.group(2) is not None else 0
            patch = int(m.group(3)) if m.group(3) is not None else 0
            # Re-split prerelease/build from the raw text so every
            # dot-separated identifier is kept.
            dash = text.find("-")
            plus = text.find("+")
            pre: Tuple[str, ...] = ()
            build: Tuple[str, ...] = ()
            if dash != -1:
                end = plus if plus != -1 else len(text)
                pre = tuple(text[dash + 1:end].split("."))
            if plus != -1:
                build = tuple(text[plus + 1:].split("."))
            canonical = self._canonical(major, minor, patch, pre, build)
            if canonical in self._by_canonical:
                raise DuplicateVersionError(
                    f"version already registered: {canonical!r}")
            self._counter += 1
            vid = f"ver-{self._counter}"
            digest = _digest({
                "canonical": canonical,
                "major": major,
                "minor": minor,
                "patch": patch,
                "prerelease": list(pre),
                "build": list(build),
                "version_id": vid,
            })
            record = VersionRecord(
                version_id=vid, original=text, major=major, minor=minor,
                patch=patch, prerelease=pre, build=build, canonical=canonical,
                digest=digest, seq=seq,
            )
            self._records[vid] = record
            self._by_canonical[canonical] = vid
            return record

    def _get(self, version_id: str) -> VersionRecord:
        record = self._records.get(version_id)
        if record is None:
            raise UnknownVersionError(f"unknown version id {version_id!r}")
        return record

    @staticmethod
    def _tuple(record: VersionRecord) -> Tuple[int, int, int, Tuple[str, ...]]:
        return (record.major, record.minor, record.patch, record.prerelease)

    def compare(self, left_id: str, right_id: str, seq: int) -> ComparisonReport:
        """Compare two registered versions; returns -1, 0, or 1."""
        with self._lock:
            seq = self._monotonic(seq)
            left = self._get(left_id)
            right = self._get(right_id)
            result = _compare_versions(self._tuple(left), self._tuple(right))
            digest = _digest({
                "left": left.canonical,
                "right": right.canonical,
                "result": result,
            })
            return ComparisonReport(
                left_id=left_id, right_id=right_id, result=result,
                left_canonical=left.canonical, right_canonical=right.canonical,
                digest=digest, seq=seq,
            )

    def satisfies(self, version_id: str, range_text: str, seq: int) -> RangeReport:
        """Evaluate a registered version against an npm-style range."""
        with self._lock:
            seq = self._monotonic(seq)
            record = self._get(version_id)
            rng = _RangeParser(range_text).parse()
            ok = _eval_range(rng, self._tuple(record))
            digest = _digest({
                "canonical": record.canonical,
                "range": range_text.strip(),
                "satisfies": ok,
            })
            return RangeReport(
                version_id=version_id, version_canonical=record.canonical,
                range_text=range_text.strip(), satisfies=ok,
                digest=digest, seq=seq,
            )

    def version(self, version_id: str) -> VersionRecord:
        """Read back a registered version record (pure view)."""
        with self._lock:
            return self._get(version_id)

    def version_ids(self) -> Tuple[str, ...]:
        """All registered version ids, oldest first."""
        with self._lock:
            return tuple(sorted(self._records, key=lambda v: int(v.split("-")[1])))

    def version_count(self) -> int:
        """Number of registered versions."""
        with self._lock:
            return len(self._records)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def version_manager_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for version-manager activity."""
    if kind not in AUDIT_KINDS:
        raise VersionError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "event": kind,
        "audit_seq": seq,
        "module_version": VERSION_MANAGER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    event.update(detail)
    return event


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    vm = VersionManager()
    v1 = vm.parse("1.2.3", 0)
    assert v1.canonical == "1.2.3" and v1.version_id == "ver-1"
    assert v1.verify()
    v2 = vm.parse("1.2.3-alpha.1", 1)
    assert v2.prerelease == ("alpha", "1")
    v3 = vm.parse("2.0.0", 2)
    # Precedence: prerelease < release; 1.2.3 < 2.0.0.
    c1 = vm.compare(v2.version_id, v1.version_id, 3)
    assert c1.result == -1, c1
    c2 = vm.compare(v1.version_id, v3.version_id, 4)
    assert c2.result == -1, c2
    c3 = vm.compare(v1.version_id, v1.version_id, 5)
    assert c3.result == 0, c3
    # Build metadata ignored for precedence/equality of the triple.
    vb = vm.parse("1.2.3+build.9", 6)
    cb = vm.compare(v1.version_id, vb.version_id, 7)
    assert cb.result == 0, cb
    # Ranges: caret, tilde, comparators, wildcards, hyphen, unions.
    r1 = vm.satisfies(v1.version_id, "^1.0.0", 8)
    assert r1.satisfies is True
    r2 = vm.satisfies(v3.version_id, "^1.0.0", 9)
    assert r2.satisfies is False
    r3 = vm.satisfies(v3.version_id, ">=1.0.0 <3.0.0 || =4.0.0", 10)
    assert r3.satisfies is True
    r4 = vm.satisfies(v1.version_id, "1.x", 11)
    assert r4.satisfies is True
    r5 = vm.satisfies(v2.version_id, "^1.0.0", 12)
    assert r5.satisfies is False  # pre-release discipline
    r6 = vm.satisfies(v2.version_id, ">=1.2.3-alpha.1 <2.0.0", 13)
    assert r6.satisfies is True
    # Fail-closed edges.
    try:
        vm.parse("01.2.3", 14)
    except BadVersionError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadVersionError")
    try:
        vm.parse("1.2.3", 15)
    except DuplicateVersionError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DuplicateVersionError")
    try:
        vm.satisfies(v1.version_id, ">=1.0.0 <<<", 16)
    except BadRangeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadRangeError")
    version_manager_audit_event(KIND_SATISFIED, 17,
                                version_id=v1.version_id, range_text="^1.0.0")
    print("version-manager OK: parse, precedence, ranges, refusals, audit")


if __name__ == "__main__":
    main()
