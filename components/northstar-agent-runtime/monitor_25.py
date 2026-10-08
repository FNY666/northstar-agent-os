"""Phishing detection: mock URL heuristics, Simulated.

Static URL-string checks (no fetching):
- IP-literal host, userinfo (@), punycode host
- lookalike of known brands (levenshtein <= 2 on host core)
- shortener hosts, suspicious TLDs, >4 labels
- http scheme with login-ish path

Score 0-100; verdict: benign (<30), suspicious (<70), phishing.

What this IS: URL-string heuristics.

What this IS NOT:
* Not content/DNS analysis -- string only, never fetched.
"""

from __future__ import annotations

import ast
import ipaddress
from dataclasses import dataclass
from typing import FrozenSet, List, Set, Tuple
from urllib.parse import urlparse

#: Module version.
MONITOR_25_VERSION = "monitor-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-25.v1"

_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
})
_SUSP_TLDS = frozenset({"tk", "ml", "ga", "cf", "gq", "xyz", "top"})
_LOGIN_HINTS = ("login", "signin", "verify", "account", "password", "secure")


class PhishError(Exception):
    """Fail-closed."""


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@dataclass(frozen=True)
class PhishVerdict:
    url: str
    verdict: str  # benign | suspicious | phishing
    score: int
    reasons: Tuple[str, ...]


class PhishDetector:
    """Static URL phishing heuristics (mock)."""

    def __init__(
        self,
        brands: FrozenSet[str] = frozenset(),
        shorteners: FrozenSet[str] = _SHORTENERS,
        susp_tlds: FrozenSet[str] = _SUSP_TLDS,
    ) -> None:
        self._brands = {b.lower() for b in brands}
        self._shorteners = set(shorteners)
        self._susp_tlds = set(susp_tlds)

    def check(self, url: str) -> PhishVerdict:
        if not url or not isinstance(url, str):
            raise PhishError("url required")
        try:
            p = urlparse(url)
        except ValueError as e:
            raise PhishError(f"unparseable url: {e}")
        if p.scheme not in ("http", "https") or not p.hostname:
            raise PhishError("url must be http(s) with a host")
        host = p.hostname.lower()
        reasons: List[str] = []
        score = 0

        def add(points: int, reason: str) -> None:
            nonlocal score
            score += points
            reasons.append(reason)

        # IP-literal host.
        try:
            ipaddress.ip_address(host)
            add(55, "ip-literal host")
        except ValueError:
            pass
        # Userinfo.
        if p.username or "@" in (p.netloc or ""):
            add(30, "userinfo/@ in authority")
        # Punycode.
        if "xn--" in host:
            add(25, "punycode host")
        # Shortener.
        if host in self._shorteners or host.endswith(
            tuple("." + s for s in self._shorteners)
        ):
            add(20, "url shortener")
        # Suspicious TLD.
        tld = host.rsplit(".", 1)[-1]
        if tld in self._susp_tlds:
            add(20, f"suspicious tld .{tld}")
        # Many labels.
        if len(host.split(".")) > 4:
            add(15, "excessive subdomains")
        # Brand lookalike: compare core label against brands.
        core = host.split(".")[0]
        for brand in self._brands:
            if core != brand and _lev(core, brand) <= 2:
                add(45, f"lookalike of brand {brand}")
                break
        # Brand as subdomain bait: paypal.com.evil.tk
        for brand in self._brands:
            if brand in host and not host.endswith("." + brand) and host != brand:
                # brand appears but is not the registrable domain
                parts = host.split(".")
                if brand not in (parts[-2] if len(parts) >= 2 else ""):
                    add(35, f"brand {brand} used as subdomain bait")
                    break
        # http + login-ish path.
        if p.scheme == "http" and any(h in p.path.lower() for h in _LOGIN_HINTS):
            add(15, "http login page")

        score = min(100, score)
        verdict = "benign" if score < 30 else ("suspicious" if score < 70 else "phishing")
        return PhishVerdict(url, verdict, score, tuple(reasons))


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "ipaddress", "pathlib",
        "typing", "urllib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    pd = PhishDetector(brands=frozenset({"paypal", "google"}))
    v = pd.check("https://www.google.com/search")
    assert v.verdict == "benign" and v.score == 0, v
    v = pd.check("http://192.168.1.1/login")
    assert "ip-literal host" in v.reasons and v.verdict == "phishing", v
    v = pd.check("https://paypa1.com/login")
    assert "lookalike of brand paypal" in v.reasons, v
    v = pd.check("https://paypal.com.evil.tk/verify")
    assert "brand paypal used as subdomain bait" in v.reasons, v
    v = pd.check("https://bit.ly/abc123")
    assert "url shortener" in v.reasons, v
    v = pd.check("https://user:pass@evil.com/")
    assert "userinfo/@ in authority" in v.reasons, v
    for bad in (
        lambda: pd.check(""),
        lambda: pd.check("ftp://x.com/"),
        lambda: pd.check("https:///nopath"),
        lambda: pd.check("notaurl"),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except PhishError:
            pass
    assert stdlib_only()
    print("monitor-25 OK: benign, ip, lookalike, bait, shortener, fail-closed, stdlib")


if __name__ == "__main__":
    main()
