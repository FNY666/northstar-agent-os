"""Vulnerability scanner: software inventory x CVE database matching (simulated).

Research note: *vulnerability management* is the operational discipline
behind OpenVAS, Nessus, Trivy, Grype, and OWASP Dependency-Check. The
load-bearing semantics are:

* **Inventory** — a bill of materials: every component's name, version,
  and (optionally) vendor/ecosystem pinned by digest.
* **CVE matching** — each CVE record names the packages it affects and the
  *affected version range* (inclusive lower bound, exclusive upper bound).
  A component matches when ``name == affected_name`` and
  ``low <= version < high`` under dotted-numeric version ordering.
* **Severity** — CVSS v3 qualitative ratings (``none`` / ``low`` /
  ``medium`` / ``high`` / ``critical``) carried as data, never as a
  priority verdict; prioritization is the caller's job.
* **Report** — a ``scan()`` returns a frozen ``ScanReport`` with
  deterministic ordering and digest pins, suitable for an audit trail.

Honest scope: this is *matching bookkeeping*, not a real scanner. It
matches *host-reported* inventory against *host-loaded* CVE records and
therefore cannot prove the inventory is complete, the CVE feed is current,
or a match is actually exploitable (``vulnerable`` means "this version
range was *declared* affected", never "this host can be exploited").
Real deployments refresh feeds from sources like the NVD and verify
exploitability out-of-band. There is no network, no feed parser, and no
real CPE dictionary here.

Version pin: vuln-scanner.v1
Schema pin: northstar.vuln-scanner.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
VULN_SCANNER_VERSION = "vuln-scanner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.vuln-scanner.v1"

#: CVSS v3 qualitative severity ratings.
SEVERITIES = ("none", "low", "medium", "high", "critical")

#: Audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "inventory-registered",
        "cve-loaded",
        "scanned",
        "matched",
        "rejected",
    }
)

#: CVE identifier grammar: CVE-YYYY-NNNN...
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

#: Package name grammar (conservative, package-manager friendly).
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,127}$")

#: Version token grammar (dotted numeric, pre-release suffixes allowed).
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]{0,63}$")


class VulnScannerError(Exception):
    """Base error for the vulnerability scanner."""


class DuplicateComponentError(VulnScannerError):
    """Inventory id registered twice."""


class UnknownComponentError(VulnScannerError):
    """Inventory id not registered."""


class DuplicateCVEError(VulnScannerError):
    """CVE id loaded twice."""


class UnknownCVEError(VulnScannerError):
    """CVE id not loaded."""


class UnknownReportError(VulnScannerError):
    """Scan report id not found."""


def _check_seq(seq: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq < 0:
        raise ValueError("seq must be >= 0")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{what} must be a non-empty str")
    return value


def _check_name(name: Any) -> str:
    name = _check_str(name, "name")
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid package name: {name!r}")
    return name


def _check_version(version: Any) -> str:
    version = _check_str(version, "version")
    if not _VERSION_RE.match(version):
        raise ValueError(f"invalid version string: {version!r}")
    return version


def _check_cve_id(cve_id: Any) -> str:
    cve_id = _check_str(cve_id, "cve_id")
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"invalid CVE id: {cve_id!r}")
    return cve_id


def _check_severity(severity: Any) -> str:
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    return severity


def _version_key(version: str) -> Tuple[Any, ...]:
    """Dotted-numeric sort key: numeric runs compare numerically.

    Non-numeric tokens compare after numeric tokens of the same position.
    This is a total order for the module's supported version grammar.
    """
    parts: list = []
    for token in version.replace("-", ".").replace("+", ".").split("."):
        if token == "":
            continue
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token))
    return tuple(parts)


def _digest(*parts: Any) -> str:
    body = jcs_canonical_json(list(parts))
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Component:
    """One inventoried software component."""

    component_id: str
    package_name: str
    version: str
    vendor: str = ""
    ecosystem: str = ""
    digest: str = ""
    seq: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "package_name": self.package_name,
            "version": self.version,
            "vendor": self.vendor,
            "ecosystem": self.ecosystem,
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": VULN_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class CVERecord:
    """One loaded CVE database entry."""

    cve_id: str
    package_name: str
    affected_low: str  # inclusive lower bound
    affected_high: str  # exclusive upper bound
    severity: str
    description: str = ""
    digest: str = ""
    seq: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "package_name": self.package_name,
            "affected_low": self.affected_low,
            "affected_high": self.affected_high,
            "severity": self.severity,
            "description": self.description,
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": VULN_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Finding:
    """One inventory x CVE match."""

    component_id: str
    cve_id: str
    severity: str
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "digest": self.digest,
            "version_pin": VULN_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ScanReport:
    """Frozen result of one scan() pass."""

    report_id: str
    seq: int
    components_scanned: int
    cves_considered: int
    findings: Tuple[Finding, ...] = ()
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "seq": self.seq,
            "components_scanned": self.components_scanned,
            "cves_considered": self.cves_considered,
            "findings": [f.as_dict() for f in self.findings],
            "digest": self.digest,
            "version_pin": VULN_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


class VulnScanner:
    """Inventory registry + CVE database + deterministic matching."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._components: Dict[str, Component] = {}
        self._cves: Dict[str, CVERecord] = {}
        self._reports: Dict[str, ScanReport] = {}
        self._report_count = 0

    # -- inventory ---------------------------------------------------

    def register_inventory(
        self,
        component_id: str,
        package_name: str,
        version: str,
        seq: int,
        vendor: str = "",
        ecosystem: str = "",
    ) -> Component:
        """Register one software component in the inventory."""
        component_id = _check_str(component_id, "component_id")
        package_name = _check_name(package_name)
        version = _check_version(version)
        _check_seq(seq)
        if not isinstance(vendor, str):
            raise TypeError("vendor must be a str")
        if not isinstance(ecosystem, str):
            raise TypeError("ecosystem must be a str")
        with self._lock:
            if component_id in self._components:
                raise DuplicateComponentError(f"duplicate component: {component_id}")
            digest = _digest(
                "component", component_id, package_name, version, vendor, ecosystem
            )
            comp = Component(
                component_id=component_id,
                package_name=package_name,
                version=version,
                vendor=vendor,
                ecosystem=ecosystem,
                digest=digest,
                seq=seq,
            )
            self._components[component_id] = comp
            return comp

    def component(self, component_id: str) -> Component:
        component_id = _check_str(component_id, "component_id")
        with self._lock:
            try:
                return self._components[component_id]
            except KeyError:
                raise UnknownComponentError(f"unknown component: {component_id}")

    def components(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._components))

    # -- CVE database ------------------------------------------------

    def load_cve(
        self,
        cve_id: str,
        package_name: str,
        affected_low: str,
        affected_high: str,
        severity: str,
        seq: int,
        description: str = "",
    ) -> CVERecord:
        """Load one CVE database entry with an affected version range."""
        cve_id = _check_cve_id(cve_id)
        package_name = _check_name(package_name)
        affected_low = _check_version(affected_low)
        affected_high = _check_version(affected_high)
        severity = _check_severity(severity)
        _check_seq(seq)
        if not isinstance(description, str):
            raise TypeError("description must be a str")
        if _version_key(affected_low) >= _version_key(affected_high):
            raise ValueError("affected_low must sort before affected_high")
        with self._lock:
            if cve_id in self._cves:
                raise DuplicateCVEError(f"duplicate CVE: {cve_id}")
            digest = _digest(
                "cve", cve_id, package_name, affected_low, affected_high, severity
            )
            rec = CVERecord(
                cve_id=cve_id,
                package_name=package_name,
                affected_low=affected_low,
                affected_high=affected_high,
                severity=severity,
                description=description,
                digest=digest,
                seq=seq,
            )
            self._cves[cve_id] = rec
            return rec

    def cve(self, cve_id: str) -> CVERecord:
        cve_id = _check_cve_id(cve_id)
        with self._lock:
            try:
                return self._cves[cve_id]
            except KeyError:
                raise UnknownCVEError(f"unknown CVE: {cve_id}")

    def cves(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._cves))

    # -- matching ----------------------------------------------------

    def _matches(self, rec: CVERecord, package_name: str, version: str) -> bool:
        if rec.package_name != package_name:
            return False
        vkey = _version_key(version)
        return (
            _version_key(rec.affected_low) <= vkey < _version_key(rec.affected_high)
        )

    def match_cve(
        self, package_name: str, version: str, seq: int
    ) -> Tuple[CVERecord, ...]:
        """Return all loaded CVE records matching (name, version)."""
        package_name = _check_name(package_name)
        version = _check_version(version)
        _check_seq(seq)
        with self._lock:
            return tuple(
                sorted(
                    (
                        rec
                        for rec in self._cves.values()
                        if self._matches(rec, package_name, version)
                    ),
                    key=lambda r: r.cve_id,
                )
            )

    def scan(self, seq: int) -> ScanReport:
        """Match every inventoried component against every loaded CVE."""
        _check_seq(seq)
        with self._lock:
            findings: list = []
            for comp in self._components.values():
                for rec in self._cves.values():
                    if self._matches(rec, comp.package_name, comp.version):
                        findings.append(
                            Finding(
                                component_id=comp.component_id,
                                cve_id=rec.cve_id,
                                severity=rec.severity,
                                digest=_digest(
                                    "finding",
                                    comp.component_id,
                                    rec.cve_id,
                                    rec.severity,
                                ),
                            )
                        )
            findings.sort(key=lambda f: (f.component_id, f.cve_id))
            self._report_count += 1
            report_id = f"scan-{self._report_count}"
            digest = _digest(
                "scan-report",
                report_id,
                [(f.component_id, f.cve_id, f.severity) for f in findings],
            )
            report = ScanReport(
                report_id=report_id,
                seq=seq,
                components_scanned=len(self._components),
                cves_considered=len(self._cves),
                findings=tuple(findings),
                digest=digest,
            )
            self._reports[report_id] = report
            return report

    def report(self, report_id: str) -> ScanReport:
        report_id = _check_str(report_id, "report_id")
        with self._lock:
            try:
                return self._reports[report_id]
            except KeyError:
                raise UnknownReportError(f"unknown report: {report_id}")

    def reports(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._reports))


def vuln_scanner_audit_event(
    kind: str,
    seq: int,
    component: Optional[Component] = None,
    cve: Optional[CVERecord] = None,
    report: Optional[ScanReport] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a scanner step."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    record: Dict[str, Any] = {
        "event": f"vuln-scanner-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if component is not None:
        if not isinstance(component, Component):
            raise TypeError("component must be a Component")
        record["component_id"] = component.component_id
        record["component_digest"] = component.digest
    if cve is not None:
        if not isinstance(cve, CVERecord):
            raise TypeError("cve must be a CVERecord")
        record["cve_id"] = cve.cve_id
        record["cve_digest"] = cve.digest
    if report is not None:
        if not isinstance(report, ScanReport):
            raise TypeError("report must be a ScanReport")
        record["report_id"] = report.report_id
        record["report_digest"] = report.digest
        record["findings"] = len(report.findings)
    return record


def main() -> None:  # pragma: no cover - self-check entry point
    sc = VulnScanner()
    sc.register_inventory("c1", "openssl", "1.1.1k", 1)
    sc.register_inventory("c2", "nginx", "1.21.0", 2)
    sc.load_cve("CVE-2021-3449", "openssl", "1.1.1a", "1.1.1l", "high", 3)
    sc.load_cve("CVE-2021-0000", "nginx", "1.22.0", "1.23.0", "low", 4)
    matches = sc.match_cve("openssl", "1.1.1k", 5)
    assert len(matches) == 1 and matches[0].cve_id == "CVE-2021-3449"
    rep = sc.scan(6)
    assert len(rep.findings) == 1
    assert rep.findings[0].cve_id == "CVE-2021-3449"
    assert rep.findings[0].severity == "high"
    print("vuln-scanner OK: register, load, match, scan, report")


if __name__ == "__main__":  # pragma: no cover
    main()
