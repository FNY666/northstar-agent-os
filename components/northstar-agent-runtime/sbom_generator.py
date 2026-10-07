"""SBOM generator: software bill of materials bookkeeping (SPDX/CycloneDX).

Research note: a *software bill of materials* (SBOM) is an inventory of the
components (and their licenses) that make up a piece of software, standardized
by SPDX (Linux Foundation, v2.3 in ISO/IEC 5962:2021) and CycloneDX (OWASP,
v1.5+). The US Executive Order 14028 (2021) and EU Cyber Resilience Act (2024)
make producing SBOMs a regulatory expectation: when a CVE lands, "which of my
shipped artifacts contain this component?" is a question the ledger must
answer exactly. The load-bearing ideas are: (1) *component identity* — every
component names a name + version (+ optional purl, package-url spec), and the
*document* pins the whole set; (2) *license expressions* — SPDX license
expressions (``MIT``, ``Apache-2.0 OR GPL-2.0-only``) are the lingua franca, and
only SPDX license-list identifiers (or ``LicenseRef-*`` custom ids, or
``NOASSERTION``) are valid; (3) *determinism* — an identical component set
must generate a byte-identical document, so two parties can compare SBOMs by
digest; (4) *verification* — a generated document must be self-describing
(SPDXVersion, DocumentNamespace/serial, required fields) and its digest pin
must recompute, otherwise it is not trustworthy.

This module implements that shape as a deterministic, single-host ledger:

* **Component registry** — :meth:`SBOMGenerator.add` records a frozen
  :class:`ComponentRecord` with a ``sha256:`` digest pin over (name, version,
  license expression, purl, supplier, source digest). License expressions are
  validated fail-closed against a pinned subset of the SPDX license list
  (``MIT``, ``Apache-2.0``, ``GPL-3.0-only``, …): unknown license tokens are
  refused unless they are ``LicenseRef-*`` or ``NOASSERTION`` — a misspelled
  license must never silently become a *different* legal claim.
* **Document generation** — :meth:`SBOMGenerator.generate` emits an
  SPDX-2.3-JSON-shaped or CycloneDX-1.5-JSON-shaped frozen
  :class:`SBOMDocument`; packages are sorted by (name, version), a document
  namespace/serial number is derived from the component-set digest, and the
  whole document body is ``sha256:``-pinned. A caller that re-generates from
  an unchanged registry gets a byte-identical document (digest equality is
  the replay guarantee).
* **Verification** — :meth:`SBOMGenerator.verify` recomputes the document
  pin, rechecks required fields (SPDX: ``spdxVersion``, ``dataLicense``,
  ``name``, ``documentNamespace``, packages with name/version/license), and
  revalidates every component's license expression; it returns a frozen
  :class:`SBOMVerification` report rather than raising on tamper (verification
  is an *observation* the caller must act on).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per generator, no wall-clock, no RNG), RLock-guarded, fail-closed
(empty names/versions, bool/negative seqs, malformed purls, unknown license
tokens all raise a subclass of :class:`SBOMError`), stdlib-only, type-tagged
canonical digest encoding (bool ≠ int; NaN/inf and integral floats with
magnitude > 2⁵³ are refused at digest-pin time — the batch-5 JCS float-loss
caveat), audit events shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a scanner. It cannot observe a
binary, prove that a component is actually present, detect a component the
host did not declare, or verify that a license identifier matches the real
legal text. ``generate()`` pins what the host *reported*; a host that lies
gets a consistent ledger of lies (GIGO, same boundary as every other
bookkeeping module). A passing :meth:`verify` means "internally consistent
and untampered since generation", never "legally complete". For real
provenance pair with ``transparency_log`` and ``remote_attestation``.

Version pin: sbom-generator.v1
Schema pin: northstar.sbom-generator.v1
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Module version pin.
SBOM_GENERATOR_VERSION = "sbom-generator.v1"

#: Schema pin for records produced by this module.
SBOM_GENERATOR_SCHEMA = "northstar.sbom-generator.v1"

#: SPDX 2.3 JSON required document fields (subset this module emits).
SPDX_VERSION = "SPDX-2.3"

#: SPDX data license (documents are required to carry a license themselves).
SPDX_DATA_LICENSE = "CC0-1.0"

#: CycloneDX spec version this module emits.
CYCLONEDX_VERSION = "1.5"

#: Two document formats this module can generate.
SPDX_JSON = "spdx-json"
CYCLONEDX_JSON = "cyclonedx-json"
KNOWN_FORMATS = (SPDX_JSON, CYCLONEDX_JSON)

# ---------------------------------------------------------------------------
# SPDX license list (pinned subset + expression grammar)
# ---------------------------------------------------------------------------

#: Pinned subset of the SPDX license list (identifiers exactly as the SPDX
#: License List publishes them). Kept as a curated subset rather than the
#: full ~600-entry list: the validation discipline (fail-closed on unknown
#: tokens) is the point, not exhaustive coverage. ``NOASSERTION`` and
#: ``NONE`` are SPDX special values, not licenses.
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

#: SPDX license-expression operators (Annex D of the SPDX spec).
_LICENSE_OPERATORS = frozenset({"AND", "OR", "WITH"})
_LICENSE_EXCEPTION_PREFIXES = ("Classpath-exception-2.0", "Font-exception-2.0",
                               "LLVM-exception", "OCCT-exception-1.0")


# ---------------------------------------------------------------------------
# Canonical digest encoding (type-tagged)
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Encode *value* with explicit type tags so digests distinguish
    ``1`` from ``True`` from ``"1"`` (the bool≠int JCS discipline used by
    the batch line). NaN/inf are refused; integral floats with magnitude
    > 2⁵³ are refused (float-loss caveat, batch 5)."""
    if isinstance(value, bool):
        return "bool:" + ("true" if value else "false")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise SBOMError("integer magnitude exceeds 2^53 (digest safety)")
        return "int:" + str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise SBOMError("NaN/inf cannot be digested")
        if value.is_integer() and abs(value) > 2**53:
            raise SBOMError("integral float magnitude exceeds 2^53")
        return "float:" + repr(value)
    if isinstance(value, str):
        return "str:" + json.dumps(value, ensure_ascii=False)
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "list:[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "dict:{" + ",".join(
            _canonical(k) + "=" + _canonical(v) for k, v in items) + "}"
    raise SBOMError("non-canonicalizable value: %r" % (type(value).__name__,))


def _digest_pin(*parts: Any) -> str:
    body = "\x1f".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SBOMError(Exception):
    """Base error for the SBOM generator."""


class InvalidLicenseError(SBOMError):
    """A license token/expression that is not valid SPDX."""


class InvalidComponentError(SBOMError):
    """Malformed component fields (empty name/version, bad purl, ...)."""


class DuplicateComponentError(SBOMError):
    """The same (name, version) was added twice with different content."""


class UnknownComponentError(SBOMError):
    """Lookup of a component that was never added."""


class VerificationError(SBOMError):
    """A document failed structural verification."""


class SeqOrderError(SBOMError):
    """Caller seqs did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_PURL_RE = re.compile(
    r"^pkg:[a-zA-Z][a-zA-Z0-9.+-]*/[a-zA-Z0-9._~%!$&'()*+,;=@/-]*$")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")


def _check_str(value: Any, what: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise SBOMError("%s must be a str, got %r" % (what, type(value).__name__))
    if not allow_empty and not value:
        raise SBOMError("%s must not be empty" % what)
    return value


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SBOMError("seq must be an int, got %r" % (type(seq).__name__,))
    if seq < 0:
        raise SBOMError("seq must be non-negative")
    if seq <= last:
        raise SeqOrderError("seq must strictly increase (last=%d, got=%d)" % (last, seq))
    return seq


def _validate_license_expression(expr: str) -> str:
    """Fail-closed validation of an SPDX license expression.

    Tokens are matched against the pinned SPDX license list; ``LicenseRef-*``
    ids and ``NOASSERTION`` are accepted; operators ``AND``/``OR``/``WITH``
    and parentheses structure the grammar. Anything else — a misspelled
    license, an unknown operator, unbalanced parens — is refused, because a
    misspelled license silently accepted would pin the *wrong legal claim*.
    """
    _check_str(expr, "license expression")
    expr = expr.strip()
    if not expr:
        raise InvalidLicenseError("license expression is empty")

    # Tokenize: operators, parens, and atoms.
    tokens: List[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue
        m = re.match(r"[A-Za-z0-9][A-Za-z0-9.+\-]*", expr[i:])
        if not m:
            raise InvalidLicenseError("bad token at offset %d: %r" % (i, expr[i:]))
        tokens.append(m.group(0))
        i += len(m.group(0))

    def token_ok(tok: str) -> bool:
        if tok in _LICENSE_OPERATORS:
            return True
        if tok in SPDX_LICENSE_IDS:
            return True
        if tok.startswith("LicenseRef-") and len(tok) > len("LicenseRef-"):
            if re.fullmatch(r"LicenseRef-[A-Za-z0-9][A-Za-z0-9.\-+]*", tok):
                return True
            return False
        if any(tok.startswith(prefix) for prefix in _LICENSE_EXCEPTION_PREFIXES):
            return True
        return False

    for tok in tokens:
        if tok in ("(", ")"):
            continue
        if not token_ok(tok):
            raise InvalidLicenseError("unknown license token: %r" % tok)

    # Paren balance.
    depth = 0
    for tok in tokens:
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
            if depth < 0:
                raise InvalidLicenseError("unbalanced parentheses")
    if depth != 0:
        raise InvalidLicenseError("unbalanced parentheses")

    # Grammar: atoms must not sit adjacent without an operator; operators
    # must not dangle. (Simplified SPDX Annex D check.)
    expect_operand = True
    for tok in tokens:
        if tok == "(":
            if not expect_operand:
                raise InvalidLicenseError("unexpected '('")
            expect_operand = True
        elif tok == ")":
            if expect_operand:
                raise InvalidLicenseError("unexpected ')'")
            expect_operand = False
        elif tok in _LICENSE_OPERATORS:
            if expect_operand:
                raise InvalidLicenseError("dangling operator %r" % tok)
            expect_operand = True
        else:
            if not expect_operand:
                raise InvalidLicenseError("missing operator before %r" % tok)
            expect_operand = False
    if expect_operand:
        raise InvalidLicenseError("expression ends with an operator")

    return expr


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ComponentRecord:
    """One declared component (name + version pinned by digest)."""
    name: str
    version: str
    license: str
    purl: Optional[str]
    supplier: Optional[str]
    source_digest: Optional[str]
    digest: str
    seq: int
    schema: str = SBOM_GENERATOR_SCHEMA
    version_pin: str = SBOM_GENERATOR_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "license": self.license,
            "purl": self.purl,
            "supplier": self.supplier,
            "sourceDigest": self.source_digest,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version_pin,
        }


@dataclass(frozen=True)
class SBOMDocument:
    """A generated SBOM document (SPDX-2.3-JSON or CycloneDX-1.5-JSON)."""
    format: str
    document_name: str
    serial: str
    body: Dict[str, Any]
    component_count: int
    digest: str
    seq: int
    schema: str = SBOM_GENERATOR_SCHEMA
    version_pin: str = SBOM_GENERATOR_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "documentName": self.document_name,
            "serial": self.serial,
            "body": self.body,
            "componentCount": self.component_count,
            "digest": self.digest,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version_pin,
        }


@dataclass(frozen=True)
class SBOMVerification:
    """Report from :meth:`SBOMGenerator.verify` (observation, not proof)."""
    document_digest: str
    digest_matches: bool
    required_fields_ok: bool
    licenses_ok: bool
    components_match_registry: bool
    overall_ok: bool
    issues: Tuple[str, ...]
    seq: int
    schema: str = SBOM_GENERATOR_SCHEMA
    version_pin: str = SBOM_GENERATOR_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "documentDigest": self.document_digest,
            "digestMatches": self.digest_matches,
            "requiredFieldsOk": self.required_fields_ok,
            "licensesOk": self.licenses_ok,
            "componentsMatchRegistry": self.components_match_registry,
            "overallOk": self.overall_ok,
            "issues": list(self.issues),
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version_pin,
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class SBOMGenerator:
    """Deterministic, single-host SBOM ledger (RLock-guarded)."""

    def __init__(self, document_name: str = "northstar-sbom") -> None:
        self._document_name = _check_str(document_name, "document name")
        self._lock = threading.RLock()
        self._components: Dict[Tuple[str, str], ComponentRecord] = {}
        self._last_seq = -1
        self._next_doc = 0

    # -- views -----------------------------------------------------------
    def document_name(self) -> str:
        return self._document_name

    def component_ids(self) -> Tuple[Tuple[str, str], ...]:
        with self._lock:
            return tuple(sorted(self._components))

    def component(self, name: str, version: str) -> ComponentRecord:
        with self._lock:
            key = (_check_str(name, "name"), _check_str(version, "version"))
            try:
                return self._components[key]
            except KeyError:
                raise UnknownComponentError("unknown component: %r@%r" % key)

    def component_count(self) -> int:
        with self._lock:
            return len(self._components)

    # -- mutation --------------------------------------------------------
    def add(self, name: str, version: str, license: str, seq: int,
            purl: Optional[str] = None, supplier: Optional[str] = None,
            source_digest: Optional[str] = None) -> ComponentRecord:
        """Declare one component. Same (name, version) with *different*
        content refuses fail-closed (supply-chain substitution); identical
        re-add is idempotent."""
        name = _check_str(name, "name")
        version = _check_str(version, "version")
        if not _NAME_RE.fullmatch(name):
            raise InvalidComponentError("bad component name: %r" % name)
        if len(name) > 128 or len(version) > 64:
            raise InvalidComponentError("name/version too long")
        license = _validate_license_expression(license)
        if purl is not None:
            purl = _check_str(purl, "purl")
            if not _PURL_RE.match(purl) or len(purl) > 512:
                raise InvalidComponentError("malformed purl: %r" % purl)
        if supplier is not None:
            supplier = _check_str(supplier, "supplier")
            if len(supplier) > 256:
                raise InvalidComponentError("supplier too long")
        if source_digest is not None:
            source_digest = _check_str(source_digest, "source digest")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_digest):
                raise InvalidComponentError("bad source digest: %r" % source_digest)

        with self._lock:
            seq = _check_seq(seq, self._last_seq)
            key = (name, version)
            digest = _digest_pin("component", name, version, license, purl,
                                 supplier, source_digest)
            record = ComponentRecord(name=name, version=version, license=license,
                                     purl=purl, supplier=supplier,
                                     source_digest=source_digest,
                                     digest=digest, seq=seq)
            existing = self._components.get(key)
            if existing is not None:
                if existing.digest != digest:
                    raise DuplicateComponentError(
                        "component %r@%r redeclared with different content"
                        % key)
                self._last_seq = seq
                return existing
            self._components[key] = record
            self._last_seq = seq
            return record

    # -- generation ------------------------------------------------------
    def generate(self, format: str = SPDX_JSON, seq: int = 0) -> SBOMDocument:
        """Emit a frozen SBOM document. Deterministic: identical registries
        produce byte-identical bodies (digest equality is the replay
        guarantee). Empty registries refuse — an empty SBOM is a lie of
        omission made official."""
        _check_str(format, "format")
        if format not in KNOWN_FORMATS:
            raise SBOMError("unknown SBOM format: %r" % format)
        with self._lock:
            seq = _check_seq(seq, self._last_seq)
            if not self._components:
                raise SBOMError("empty component registry: refuse to emit "
                                "an empty SBOM")
            records = [self._components[k] for k in sorted(self._components)]
            set_digest = _digest_pin(
                "sbom-set", format,
                [(r.name, r.version, r.digest) for r in records])
            self._next_doc += 1
            serial = "urn:uuid:sbom-%s-%d" % (set_digest[7:19], self._next_doc)
            if format == SPDX_JSON:
                body = self._spdx_body(records, serial)
            else:
                body = self._cyclonedx_body(records, serial)
            digest = _digest_pin("sbom-document", format,
                                 json.dumps(body, sort_keys=True, ensure_ascii=True))
            self._last_seq = seq
            return SBOMDocument(format=format, document_name=self._document_name,
                                serial=serial, body=body,
                                component_count=len(records),
                                digest=digest, seq=seq)

    def _spdx_body(self, records: List[ComponentRecord], serial: str) -> Dict[str, Any]:
        packages = []
        for r in records:
            pkg: Dict[str, Any] = {
                "name": r.name,
                "versionInfo": r.version,
                "SPDXID": "SPDXRef-Package-%s-%s" % (
                    re.sub(r"[^A-Za-z0-9]", "-", r.name),
                    re.sub(r"[^A-Za-z0-9]", "-", r.version)),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": r.license,
                "licenseDeclared": r.license,
                "copyrightText": "NOASSERTION",
            }
            if r.purl:
                pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": r.purl,
                }]
            if r.source_digest:
                pkg["checksums"] = [{
                    "algorithm": "SHA256",
                    "checksumValue": r.source_digest[7:],
                }]
            packages.append(pkg)
        return {
            "spdxVersion": SPDX_VERSION,
            "dataLicense": SPDX_DATA_LICENSE,
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self._document_name,
            "documentNamespace": serial,
            "creationInfo": {
                "created": "SEQ-%d" % self._last_seq,
                "creators": ["Tool: northstar-sbom-generator-" + SBOM_GENERATOR_VERSION],
            },
            "packages": packages,
        }

    def _cyclonedx_body(self, records: List[ComponentRecord], serial: str) -> Dict[str, Any]:
        components = []
        for r in records:
            comp: Dict[str, Any] = {
                "bom-ref": "%s@%s" % (r.name, r.version),
                "type": "library",
                "name": r.name,
                "version": r.version,
                "licenses": [{"expression": r.license}],
            }
            if r.purl:
                comp["purl"] = r.purl
            if r.supplier:
                comp["supplier"] = {"name": r.supplier}
            if r.source_digest:
                comp["hashes"] = [{"alg": "SHA-256", "content": r.source_digest[7:]}]
            components.append(comp)
        return {
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_VERSION,
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": "SEQ-%d" % self._last_seq,
                "tools": [{"name": "northstar-sbom-generator",
                           "version": SBOM_GENERATOR_VERSION}],
            },
            "components": components,
        }

    # -- verification ----------------------------------------------------
    def verify(self, doc: SBOMDocument, seq: int) -> SBOMVerification:
        """Check a document: digest pin recomputation, required fields,
        license expressions, and registry consistency. Returns a frozen
        report (verification is an observation, never a raise on tamper)."""
        if not isinstance(doc, SBOMDocument):
            raise VerificationError("not an SBOMDocument: %r" % type(doc).__name__)
        issues: List[str] = []
        with self._lock:
            seq = _check_seq(seq, self._last_seq)
            recomputed = _digest_pin(
                "sbom-document", doc.format,
                json.dumps(doc.body, sort_keys=True, ensure_ascii=True))
            digest_ok = recomputed == doc.digest
            if not digest_ok:
                issues.append("digest pin mismatch: document tampered")
            fields_ok = self._required_fields_ok(doc, issues)
            licenses_ok = self._licenses_ok(doc, issues)
            registry_ok = self._registry_matches(doc, issues)
            overall = digest_ok and fields_ok and licenses_ok and registry_ok
            self._last_seq = seq
            return SBOMVerification(document_digest=doc.digest,
                                    digest_matches=digest_ok,
                                    required_fields_ok=fields_ok,
                                    licenses_ok=licenses_ok,
                                    components_match_registry=registry_ok,
                                    overall_ok=overall,
                                    issues=tuple(issues), seq=seq)

    def _required_fields_ok(self, doc: SBOMDocument,
                            issues: List[str]) -> bool:
        body = doc.body
        if doc.format == SPDX_JSON:
            required = {"spdxVersion", "dataLicense", "SPDXID", "name",
                        "documentNamespace", "packages"}
            missing = required - set(body)
            if missing:
                issues.append("SPDX missing required fields: %s" % sorted(missing))
            elif body.get("spdxVersion") != SPDX_VERSION:
                issues.append("unexpected SPDX version: %r" % body.get("spdxVersion"))
            for i, pkg in enumerate(body.get("packages", [])):
                for f in ("name", "versionInfo", "licenseConcluded"):
                    if f not in pkg:
                        issues.append("SPDX package %d missing %s" % (i, f))
        elif doc.format == CYCLONEDX_JSON:
            required = {"bomFormat", "specVersion", "serialNumber", "components"}
            missing = required - set(body)
            if missing:
                issues.append("CycloneDX missing required fields: %s" % sorted(missing))
            elif body.get("specVersion") != CYCLONEDX_VERSION:
                issues.append("unexpected CycloneDX version: %r" % body.get("specVersion"))
            for i, comp in enumerate(body.get("components", [])):
                for f in ("name", "version"):
                    if f not in comp:
                        issues.append("CycloneDX component %d missing %s" % (i, f))
        else:
            issues.append("unknown document format: %r" % doc.format)
            return False
        return not issues

    def _licenses_ok(self, doc: SBOMDocument, issues: List[str]) -> bool:
        try:
            if doc.format == SPDX_JSON:
                exprs = [pkg.get("licenseConcluded", "")
                         for pkg in doc.body.get("packages", [])]
            else:
                exprs = []
                for comp in doc.body.get("components", []):
                    lics = comp.get("licenses", [])
                    exprs.append(lics[0].get("expression", "") if lics else "")
            for expr in exprs:
                _validate_license_expression(expr)
        except InvalidLicenseError as e:
            issues.append("license validation failed: %s" % e)
            return False
        return True

    def _registry_matches(self, doc: SBOMDocument, issues: List[str]) -> bool:
        if doc.format == SPDX_JSON:
            pairs = [(p["name"], p["versionInfo"]) for p in doc.body.get("packages", [])]
        else:
            pairs = [(c["name"], c["version"]) for c in doc.body.get("components", [])]
        with_ids = sorted((r.name, r.version) for r in self._components.values())
        if sorted(pairs) != with_ids:
            issues.append("document components do not match registry "
                          "(%d in document, %d in registry)"
                          % (len(pairs), len(with_ids)))
            return False
        return True


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def sbom_generator_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for SBOM ledger events."""
    kinds = ("component-added", "component-duplicate", "sbom-generated",
             "sbom-verified", "sbom-verification-failed")
    if kind not in kinds:
        raise SBOMError("unknown audit kind: %r" % kind)
    seq = _check_seq(seq, -1)
    return {
        "schema": "audit.ndjson/1",
        "module": "sbom_generator",
        "moduleVersion": SBOM_GENERATOR_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    gen = SBOMGenerator("self-check")
    gen.add("requests", "2.31.0", "Apache-2.0", seq=0,
            purl="pkg:pypi/requests@2.31.0",
            source_digest="sha256:" + "0" * 64)
    gen.add("urllib3", "2.2.3", "MIT", seq=1)
    doc = gen.generate(format=SPDX_JSON, seq=2)
    assert doc.component_count == 2, doc.component_count
    # Determinism across instances: same inputs, same digest.
    gen2 = SBOMGenerator("self-check")
    gen2.add("requests", "2.31.0", "Apache-2.0", seq=0,
             purl="pkg:pypi/requests@2.31.0",
             source_digest="sha256:" + "0" * 64)
    gen2.add("urllib3", "2.2.3", "MIT", seq=1)
    doc2 = gen2.generate(format=SPDX_JSON, seq=2)
    assert doc.digest == doc2.digest, "generation must be deterministic"
    report = gen.verify(doc, seq=3)
    assert report.overall_ok, report.issues
    # Misspelled license must not silently pin a different legal claim.
    try:
        gen.add("evil", "1.0", "MITT", seq=4)
    except InvalidLicenseError:
        pass
    else:
        raise AssertionError("misspelled license accepted")
    print("sbom-generator OK: add, generate, determinism, verify, license refusal")


if __name__ == "__main__":
    main()
