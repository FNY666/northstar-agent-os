"""DAST scanner: crawl x attack-template bookkeeping (OWASP ZAP shaped, simulated).

Research note: *dynamic application security testing* (DAST) is the
operational discipline behind OWASP ZAP, Burp Suite, and Acunetix. The
load-bearing semantics are:

* **Crawl (spider)** — from a seed URL, the scanner discovers pages,
  their forms, query params, and links. ZAP scopes the spider to the
  target origin: off-origin pages are not spidered in-scope.
* **Attack templates** — a pinned library of attack kinds (injection,
  XSS, SSRF, path traversal, ...), each with a severity, shaped like
  ZAP's active-scan rules. Loading a template is a registry act, not
  an execution.
* **Attack (active scan)** — for each crawled page, the host *reports*
  which (page, attack) pairs produced evidence (a reflected payload,
  an error signature, a missing header). The module books those
  observations as findings; it never executes HTTP requests itself.
* **Report** — a frozen ``ScanReport`` aggregates every attack report
  for a crawl, with deterministic ordering and digest pins, suitable
  for an audit trail.

Honest scope: this is *scan bookkeeping*, not a real DAST engine. It
books *host-reported* crawl results and *host-reported* attack
observations, so it cannot prove a page was actually fetched, an attack
actually ran, or a finding is actually exploitable (a finding means
"the host reported evidence for this (page, attack) pair", never "this
host is vulnerable"). There is no network, no payload engine, and no
browser here. Pair with a real scanner (ZAP/Burp) plus an attested
host to make the ledger mean something.

Version pin: dast-scanner.v1
Schema pin: northstar.dast-scanner.v1
"""

from __future__ import annotations

import hashlib
import math
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
DAST_SCANNER_VERSION = "dast-scanner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.dast-scanner.v1"

#: ZAP-style risk ratings carried as data, never as a priority verdict.
SEVERITIES = ("info", "low", "medium", "high")

#: Pinned attack-template categories (OWASP Top-10 shaped vocabulary).
CATEGORIES = (
    "injection",
    "xss",
    "broken-access-control",
    "misconfiguration",
    "auth-failure",
    "ssrf",
    "sensitive-data",
    "crypto-failure",
)

#: Audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "attack-loaded",
        "crawled",
        "attacked",
        "reported",
        "rejected",
    }
)

#: Attack id grammar (lowercase, dashes, digits).
_ATTACK_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

#: Conservative absolute-URL grammar (no userinfo, no whitespace).
_URL_RE = re.compile(r"^https?://[^\s/@]+(:\d+)?(/[^\s]*)?$")

#: Evidence is a host-reported string, bounded to keep records small.
_MAX_EVIDENCE_BYTES = 4096

#: Maximum pages booked into one crawl.
_MAX_PAGES = 10000

#: Maximum observations booked into one attack report.
_MAX_OBSERVATIONS = 100000


class DASTScannerError(Exception):
    """Base error for the DAST scanner."""


class DuplicateAttackError(DASTScannerError):
    """Attack id loaded twice."""


class UnknownAttackError(DASTScannerError):
    """Attack id not loaded."""


class UnknownCrawlError(DASTScannerError):
    """Crawl id not found."""


class UnknownPageError(DASTScannerError):
    """Page URL not crawled in this crawl."""


class UnknownReportError(DASTScannerError):
    """Report id not found."""


class BadURLError(DASTScannerError):
    """Seed or page URL is malformed or out of scope."""


class BadPageError(DASTScannerError):
    """Page spec is malformed (bad shape, duplicates, scope)."""


class DuplicateObservationError(DASTScannerError):
    """Same (page_url, attack_id) observed twice in one attack."""


class SeqOrderError(DASTScannerError):
    """Mutation seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq < 0:
        raise ValueError("seq must be >= 0")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{what} must be a non-empty str")
    return value


def _check_attack_id(attack_id: Any) -> str:
    attack_id = _check_str(attack_id, "attack_id")
    if not _ATTACK_ID_RE.match(attack_id):
        raise ValueError(f"invalid attack id: {attack_id!r}")
    return attack_id


def _check_category(category: Any) -> str:
    if not isinstance(category, str) or category not in CATEGORIES:
        raise ValueError(f"category must be one of {CATEGORIES}")
    return category


def _check_severity(severity: Any) -> str:
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    return severity


def _check_url(url: Any, what: str = "url") -> str:
    url = _check_str(url, what)
    if len(url) > 2048:
        raise BadURLError(f"{what} too long: {url!r}")
    if not _URL_RE.match(url):
        raise BadURLError(f"invalid {what}: {url!r}")
    return url


def _origin(url: str) -> str:
    """scheme://host[:port] of an absolute URL."""
    scheme, _, rest = url.partition("://")
    host = rest.split("/", 1)[0]
    return scheme.lower() + "://" + host.lower()


def _tag(value: Any) -> Any:
    """Type-tagged canonical encoding: bool != int, NaN/inf and >= 2**53
    integral floats refused (the batch-5 JCS float-loss discipline)."""
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise ValueError("integer out of safe range")
        return ("int", value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/inf not encodable")
        if not value.is_integer() or abs(value) >= 2**53:
            raise ValueError("non-integral or out-of-range float")
        return ("int", int(value))
    if isinstance(value, str):
        return ("str", value)
    if value is None:
        return ("none",)
    if isinstance(value, (tuple, list)):
        return ("list", [_tag(v) for v in value])
    if isinstance(value, Mapping):
        return ("dict", sorted(((k, _tag(v)) for k, v in value.items())))
    raise TypeError(f"not encodable: {type(value).__name__}")


def _digest(*parts: Any) -> str:
    body = jcs_canonical_json([_tag(p) for p in parts])
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class AttackRecord:
    """One loaded attack template (ZAP active-scan-rule shaped)."""

    attack_id: str
    name: str
    category: str
    severity: str
    description: str = ""
    digest: str = ""
    seq: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class PageRecord:
    """One crawled page: forms, params, and links, all host-reported."""

    page_id: str
    crawl_id: str
    url: str
    forms: Tuple[str, ...] = ()
    params: Tuple[str, ...] = ()
    links: Tuple[str, ...] = ()
    digest: str = ""
    seq: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "page_id": self.page_id,
            "crawl_id": self.crawl_id,
            "url": self.url,
            "forms": list(self.forms),
            "params": list(self.params),
            "links": list(self.links),
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class CrawlRecord:
    """One finished crawl: the seed plus every in-scope page."""

    crawl_id: str
    seed_url: str
    pages: Tuple[PageRecord, ...] = ()
    digest: str = ""
    seq: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "crawl_id": self.crawl_id,
            "seed_url": self.seed_url,
            "pages": [p.as_dict() for p in self.pages],
            "digest": self.digest,
            "seq": self.seq,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Finding:
    """One booked attack observation: evidence reported for (page, attack)."""

    page_url: str
    attack_id: str
    severity: str
    evidence_digest: str = ""
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "page_url": self.page_url,
            "attack_id": self.attack_id,
            "severity": self.severity,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class AttackReport:
    """Frozen result of one attack() pass over a crawl."""

    report_id: str
    crawl_id: str
    seq: int
    attacks_considered: int
    findings: Tuple[Finding, ...] = ()
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "crawl_id": self.crawl_id,
            "seq": self.seq,
            "attacks_considered": self.attacks_considered,
            "findings": [f.as_dict() for f in self.findings],
            "digest": self.digest,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ScanReport:
    """Frozen aggregate: every attack report for one crawl."""

    report_id: str
    crawl_id: str
    seq: int
    pages_scanned: int
    attack_reports: int
    findings: Tuple[Finding, ...] = ()
    digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "crawl_id": self.crawl_id,
            "seq": self.seq,
            "pages_scanned": self.pages_scanned,
            "attack_reports": self.attack_reports,
            "findings": [f.as_dict() for f in self.findings],
            "digest": self.digest,
            "version_pin": DAST_SCANNER_VERSION,
            "schema": SCHEMA_PIN,
        }


class DASTScanner:
    """Attack-template registry + crawl ledger + observation bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._attacks: Dict[str, AttackRecord] = {}
        self._crawls: Dict[str, CrawlRecord] = {}
        self._attack_reports: Dict[str, AttackReport] = {}
        self._crawl_attack_reports: Dict[str, List[str]] = {}
        self._scan_reports: Dict[str, ScanReport] = {}
        self._crawl_count = 0
        self._attack_report_count = 0
        self._scan_report_count = 0
        self._last_seq = -1

    # -- seq discipline ------------------------------------------------

    def _monotonic(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("mutation seq must strictly increase")
        self._last_seq = seq
        return seq

    # -- attack template library ---------------------------------------

    def load_attack(
        self,
        attack_id: str,
        name: str,
        category: str,
        severity: str,
        seq: int,
        description: str = "",
    ) -> AttackRecord:
        """Load one attack template into the registry."""
        attack_id = _check_attack_id(attack_id)
        name = _check_str(name, "name")
        category = _check_category(category)
        severity = _check_severity(severity)
        if not isinstance(description, str):
            raise TypeError("description must be a str")
        self._monotonic(seq)
        with self._lock:
            if attack_id in self._attacks:
                raise DuplicateAttackError(f"attack {attack_id!r} already loaded")
            rec = AttackRecord(
                attack_id=attack_id,
                name=name,
                category=category,
                severity=severity,
                description=description,
                digest=_digest("attack", attack_id, name, category, severity),
                seq=seq,
            )
            self._attacks[attack_id] = rec
            return rec

    def attack_template(self, attack_id: str) -> AttackRecord:
        _check_attack_id(attack_id)
        with self._lock:
            try:
                return self._attacks[attack_id]
            except KeyError:
                raise UnknownAttackError(f"unknown attack: {attack_id!r}")

    def attack_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._attacks))

    # -- crawl ----------------------------------------------------------

    @staticmethod
    def _check_page_spec(spec: Any, seed_origin: str) -> Tuple[str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
        if not isinstance(spec, Mapping):
            raise BadPageError("page spec must be a mapping")
        url = _check_url(spec.get("url"), "page url")
        if _origin(url) != seed_origin:
            raise BadPageError(f"page out of crawl scope: {url!r}")
        forms: List[str] = []
        for f in spec.get("forms", ()):
            forms.append(_check_str(f, "form"))
        params: List[str] = []
        for p in spec.get("params", ()):
            params.append(_check_str(p, "param"))
        links: List[str] = []
        for l in spec.get("links", ()):
            links.append(_check_url(l, "link"))
        return url, tuple(forms), tuple(params), tuple(links)

    def crawl(
        self,
        seed_url: str,
        seq: int,
        pages: Tuple[Mapping[str, Any], ...] = (),
    ) -> CrawlRecord:
        """Book one finished crawl: seed plus host-reported in-scope pages."""
        seed_url = _check_url(seed_url, "seed url")
        seed_origin = _origin(seed_url)
        if not isinstance(pages, (tuple, list)):
            raise TypeError("pages must be a tuple/list of page specs")
        if len(pages) > _MAX_PAGES:
            raise BadPageError("too many pages in one crawl")
        checked: List[Tuple[str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = [
            self._check_page_spec(spec, seed_origin) for spec in pages
        ]
        seen = set()
        for url, _, _, _ in checked:
            if url in seen:
                raise BadPageError(f"duplicate page in crawl: {url!r}")
            seen.add(url)
        self._monotonic(seq)
        with self._lock:
            self._crawl_count += 1
            crawl_id = f"crawl-{self._crawl_count}"
            page_records = tuple(
                PageRecord(
                    page_id=f"{crawl_id}-page-{i + 1}",
                    crawl_id=crawl_id,
                    url=url,
                    forms=forms,
                    params=params,
                    links=links,
                    digest=_digest("page", crawl_id, url, forms, params, links),
                    seq=seq,
                )
                for i, (url, forms, params, links) in enumerate(checked)
            )
            rec = CrawlRecord(
                crawl_id=crawl_id,
                seed_url=seed_url,
                pages=page_records,
                digest=_digest(
                    "crawl",
                    crawl_id,
                    seed_url,
                    sorted(url for url, _, _, _ in checked),
                ),
                seq=seq,
            )
            self._crawls[crawl_id] = rec
            self._crawl_attack_reports[crawl_id] = []
            return rec

    def crawl_record(self, crawl_id: str) -> CrawlRecord:
        _check_str(crawl_id, "crawl_id")
        with self._lock:
            try:
                return self._crawls[crawl_id]
            except KeyError:
                raise UnknownCrawlError(f"unknown crawl: {crawl_id!r}")

    def crawl_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._crawls))

    # -- attack ---------------------------------------------------------

    def attack(
        self,
        crawl_id: str,
        seq: int,
        observations: Tuple[Mapping[str, Any], ...] = (),
    ) -> AttackReport:
        """Book one attack pass: host-reported (page, attack) observations."""
        _check_str(crawl_id, "crawl_id")
        if not isinstance(observations, (tuple, list)):
            raise TypeError("observations must be a tuple/list of mappings")
        if len(observations) > _MAX_OBSERVATIONS:
            raise DASTScannerError("too many observations in one attack")
        self._monotonic(seq)
        with self._lock:
            try:
                crawl = self._crawls[crawl_id]
            except KeyError:
                raise UnknownCrawlError(f"unknown crawl: {crawl_id!r}")
            crawled = {p.url for p in crawl.pages}
            self._attack_report_count += 1
            report_id = f"attack-{self._attack_report_count}"
            findings: List[Finding] = []
            seen_pairs = set()
            for obs in observations:
                if not isinstance(obs, Mapping):
                    raise TypeError("observation must be a mapping")
                page_url = obs.get("page_url")
                attack_id = obs.get("attack_id")
                evidence = obs.get("evidence", "")
                if not isinstance(page_url, str) or not page_url:
                    raise UnknownPageError("observation needs a page_url")
                if page_url not in crawled:
                    raise UnknownPageError(f"page not crawled: {page_url!r}")
                attack_id = _check_attack_id(attack_id)
                try:
                    tmpl = self._attacks[attack_id]
                except KeyError:
                    raise UnknownAttackError(f"unknown attack: {attack_id!r}")
                if not isinstance(evidence, str) or not evidence:
                    raise TypeError("evidence must be a non-empty str")
                if len(evidence.encode("utf-8")) > _MAX_EVIDENCE_BYTES:
                    raise DASTScannerError("evidence too large")
                if (page_url, attack_id) in seen_pairs:
                    raise DuplicateObservationError(
                        f"duplicate observation: {page_url!r} x {attack_id!r}"
                    )
                seen_pairs.add((page_url, attack_id))
                evidence_digest = _digest("evidence", report_id, page_url, attack_id, evidence)
                findings.append(
                    Finding(
                        page_url=page_url,
                        attack_id=attack_id,
                        severity=tmpl.severity,
                        evidence_digest=evidence_digest,
                        digest=_digest(
                            "finding", page_url, attack_id, tmpl.severity, evidence_digest
                        ),
                    )
                )
            findings.sort(key=lambda f: (f.page_url, f.attack_id))
            report = AttackReport(
                report_id=report_id,
                crawl_id=crawl_id,
                seq=seq,
                attacks_considered=len(self._attacks),
                findings=tuple(findings),
                digest=_digest(
                    "attack-report",
                    report_id,
                    crawl_id,
                    [(f.page_url, f.attack_id) for f in findings],
                ),
            )
            self._attack_reports[report_id] = report
            self._crawl_attack_reports[crawl_id].append(report_id)
            return report

    # -- report ----------------------------------------------------------

    def report(self, crawl_id: str, seq: int) -> ScanReport:
        """Aggregate every attack report for a crawl into one frozen report."""
        _check_str(crawl_id, "crawl_id")
        self._monotonic(seq)
        with self._lock:
            try:
                crawl = self._crawls[crawl_id]
            except KeyError:
                raise UnknownCrawlError(f"unknown crawl: {crawl_id!r}")
            merged: List[Finding] = []
            for rid in self._crawl_attack_reports[crawl_id]:
                merged.extend(self._attack_reports[rid].findings)
            merged.sort(key=lambda f: (f.page_url, f.attack_id))
            self._scan_report_count += 1
            report_id = f"scan-{self._scan_report_count}"
            report = ScanReport(
                report_id=report_id,
                crawl_id=crawl_id,
                seq=seq,
                pages_scanned=len(crawl.pages),
                attack_reports=len(self._crawl_attack_reports[crawl_id]),
                findings=tuple(merged),
                digest=_digest(
                    "scan-report",
                    report_id,
                    crawl_id,
                    [(f.page_url, f.attack_id) for f in merged],
                ),
            )
            self._scan_reports[report_id] = report
            return report

    def get_report(self, report_id: str) -> ScanReport:
        report_id = _check_str(report_id, "report_id")
        with self._lock:
            try:
                return self._scan_reports[report_id]
            except KeyError:
                raise UnknownReportError(f"unknown report: {report_id!r}")

    def report_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._scan_reports))


def dast_scanner_audit_event(
    kind: str,
    seq: int,
    crawl: Optional[CrawlRecord] = None,
    attack: Optional[AttackRecord] = None,
    report: Optional[ScanReport] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a scanner step."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    record: Dict[str, Any] = {
        "event": f"dast-scanner-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if attack is not None:
        if not isinstance(attack, AttackRecord):
            raise TypeError("attack must be an AttackRecord")
        record["attack_id"] = attack.attack_id
        record["attack_digest"] = attack.digest
    if crawl is not None:
        if not isinstance(crawl, CrawlRecord):
            raise TypeError("crawl must be a CrawlRecord")
        record["crawl_id"] = crawl.crawl_id
        record["crawl_digest"] = crawl.digest
        record["pages"] = len(crawl.pages)
    if report is not None:
        if not isinstance(report, ScanReport):
            raise TypeError("report must be a ScanReport")
        record["report_id"] = report.report_id
        record["report_digest"] = report.digest
        record["findings"] = len(report.findings)
    return record


def main() -> None:  # pragma: no cover - self-check entry point
    sc = DASTScanner()
    sc.load_attack("xss-reflected", "Reflected XSS", "xss", "high", 1)
    sc.load_attack("missing-csp", "Missing CSP header", "misconfiguration", "low", 2)
    cr = sc.crawl(
        "https://app.example/",
        3,
        pages=(
            {"url": "https://app.example/", "forms": (), "params": (), "links": ()},
            {
                "url": "https://app.example/search",
                "forms": ("q",),
                "params": ("q",),
                "links": (),
            },
        ),
    )
    assert len(cr.pages) == 2
    ar = sc.attack(
        cr.crawl_id,
        4,
        observations=(
            {
                "page_url": "https://app.example/search",
                "attack_id": "xss-reflected",
                "evidence": "<script>alert(1)</script> reflected",
            },
        ),
    )
    assert len(ar.findings) == 1
    rep = sc.report(cr.crawl_id, 5)
    assert len(rep.findings) == 1
    assert rep.findings[0].severity == "high"
    print("dast-scanner OK: load, crawl, attack, report")


if __name__ == "__main__":  # pragma: no cover
    main()
