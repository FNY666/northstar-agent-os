"""IOC matching: match indicators against observables, Simulated.

Matches observables (ip, domain, url, hash) against an IOC set using:
- exact match (ip/domain/hash)
- CIDR subnet containment (ip against ip/CIDR indicators)
- domain suffix (subdomain of an indicator domain)
- URL host extraction (match URL against domain/ip indicators)

What this IS: the lookup layer over monitor_10's feed.

What this IS NOT:
* Not fuzzy matching -- exact, CIDR, or suffix only.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_11_VERSION = "monitor-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-11.v1"

_VALID_OBS = {"ip", "domain", "url", "hash"}


class IocMatchError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Match:
    observable: str
    obs_type: str
    indicator: str
    match_kind: str  # exact | cidr | suffix | url_host
    confidence: int


class IocMatcher:
    """Stateless matcher over a plain indicator list."""

    def __init__(self, indicators: List[Dict[str, Any]]) -> None:
        self._inds: List[Dict[str, Any]] = []
        for ind in indicators:
            t = ind.get("type")
            v = ind.get("value", "")
            c = int(ind.get("confidence", 50))
            if t not in _VALID_OBS and t != "cidr":
                raise IocMatchError(f"bad indicator type {t!r}")
            if not isinstance(v, str) or not v:
                raise IocMatchError("indicator value required")
            if not 0 <= c <= 100:
                raise IocMatchError("confidence must be 0-100")
            self._inds.append({"type": t, "value": v.lower(), "confidence": c})

    def _match_ip(self, obs: str) -> List[Match]:
        out: List[Match] = []
        try:
            addr = ipaddress.ip_address(obs)
        except ValueError:
            raise IocMatchError(f"bad ip observable {obs!r}")
        for ind in self._inds:
            if ind["type"] == "ip" and ind["value"] == obs.lower():
                out.append(Match(obs, "ip", ind["value"], "exact", ind["confidence"]))
            elif ind["type"] == "cidr":
                try:
                    if addr in ipaddress.ip_network(ind["value"], strict=False):
                        out.append(
                            Match(obs, "ip", ind["value"], "cidr", ind["confidence"])
                        )
                except ValueError:
                    continue
        return out

    def _match_domain(self, obs: str) -> List[Match]:
        out: List[Match] = []
        obs_l = obs.lower()
        for ind in self._inds:
            if ind["type"] != "domain":
                continue
            if ind["value"] == obs_l:
                out.append(Match(obs, "domain", ind["value"], "exact", ind["confidence"]))
            elif obs_l.endswith("." + ind["value"]):
                out.append(Match(obs, "domain", ind["value"], "suffix", ind["confidence"]))
        return out

    def match(self, obs_type: str, observable: str) -> List[Match]:
        """Match one observable. Returns all matches (may be empty)."""
        if obs_type not in _VALID_OBS:
            raise IocMatchError(f"bad observable type {obs_type!r}")
        if not isinstance(observable, str) or not observable:
            raise IocMatchError("observable required")
        if obs_type == "ip":
            return self._match_ip(observable)
        if obs_type == "domain":
            return self._match_domain(observable)
        if obs_type == "url":
            m = re.match(r"^https?://([^/:]+)", observable.lower())
            if not m:
                raise IocMatchError(f"bad url observable {observable!r}")
            host = m.group(1)
            out: List[Match] = []
            for ind in self._inds:
                if ind["type"] in ("domain", "ip") and ind["value"] == host:
                    out.append(
                        Match(observable, "url", ind["value"], "url_host", ind["confidence"])
                    )
                elif ind["type"] == "domain" and host.endswith("." + ind["value"]):
                    out.append(
                        Match(observable, "url", ind["value"], "url_host", ind["confidence"])
                    )
            return out
        # hash: exact only.
        return [
            Match(observable, "hash", ind["value"], "exact", ind["confidence"])
            for ind in self._inds
            if ind["type"] == "hash" and ind["value"] == observable.lower()
        ]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "ipaddress", "pathlib", "re", "typing"}
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
    m = IocMatcher(
        [
            {"type": "ip", "value": "1.2.3.4", "confidence": 90},
            {"type": "cidr", "value": "10.0.0.0/8", "confidence": 70},
            {"type": "domain", "value": "evil.example", "confidence": 80},
        ]
    )
    assert len(m.match("ip", "1.2.3.4")) == 1
    assert m.match("ip", "1.2.3.4")[0].match_kind == "exact"
    assert m.match("ip", "10.1.2.3")[0].match_kind == "cidr"
    assert m.match("ip", "8.8.8.8") == []
    assert m.match("domain", "sub.evil.example")[0].match_kind == "suffix"
    assert m.match("url", "http://evil.example/x")[0].match_kind == "url_host"
    try:
        m.match("bogus", "x")
        raise AssertionError("should raise")
    except IocMatchError:
        pass
    try:
        m.match("ip", "not-an-ip")
        raise AssertionError("should raise")
    except IocMatchError:
        pass
    assert stdlib_only()
    print("monitor-11 OK: exact/cidr/suffix/url_host, fail-closed, stdlib")


if __name__ == "__main__":
    main()
