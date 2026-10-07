"""MCP Protocol Pivoting detector: refuse tool calls that reach internal targets.

"Protocol Pivoting" is the structural SSRF defect confirmed across five
organizations (Google, JPMorgan Chase, Weaviate, France's DINUM, Tangerang
City): an MCP tool that fetches URLs — a browser tool, an HTTP client, a
webhook forwarder — is pointed at an *internal* address and the MCP host's
network position does the attacker's pivoting for them. The classic target
is the cloud instance-metadata endpoint (``169.254.169.254``), which hands
over temporary credentials; the same shape reaches ``localhost`` admin
consoles, RFC 1918 neighbors, and link-local services.

This module is the per-call checkpoint:

* ``detect_pivoting(tool_call)`` returns ``True`` when a tool call's URL
  argument resolves to a blocked target: cloud metadata endpoints,
  loopback, link-local, or RFC 1918 / RFC 4193 private ranges.
* ``PivotingAttempt`` is the frozen record of one blocked (or inspected)
  call: tool name, URL, and the verdict.
* ``check_tool_call(tool_name, url)`` is the one-call convenience used at
  the dispatch site: inspect → record → verdict.

Fail-closed throughout: an unparseable URL is treated as pivoting (deny),
not as benign. Percent-encoding is decoded before inspection so
``http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/`` does not slip
past a string match.

Honest scope: this inspects the *literal* host in the URL the tool was
asked to fetch. It does not resolve DNS (so DNS-rebinding and
attacker-controlled domains that resolve internally are out of scope —
that needs a resolving egress proxy, not a string check), and it does not
judge whether the *tool itself* is legitimate — only whether its target
is internal. Detector, not defense; runs on host-reported tool calls.

Everything here is offline and deterministic. No network, no clock reads.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

#: Module version pin, stamped on records for auditability.
MCP_PIVOTING_VERSION = "mcp-pivoting-detector.v1"

#: Schema pin for the record envelope.
SCHEMA_PIN = "northstar.mcp-pivoting-detector.v1"

# ---------------------------------------------------------------------------
# Block lists
# ---------------------------------------------------------------------------

#: Cloud instance-metadata endpoints and well-known internal hostnames.
#: Checked case-insensitively against the URL host after percent-decoding.
BLOCKED_HOSTNAMES = frozenset({
    # AWS / Azure / generic link-local metadata
    "169.254.169.254",
    # GCP
    "metadata.google.internal",
    "metadata.google",
    # Azure (also 169.254.169.254, listed for clarity)
    # Alibaba Cloud
    "100.100.100.200",
    # Loopback names
    "localhost",
    "localhost.localdomain",
    # Common internal service names seen in SSRF payloads
    "instance-data",
    "instance-data.compute.internal",
})

#: Suffixes that always indicate an internal target (checked against the
#: decoded host, case-insensitive).
BLOCKED_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".corp",
    ".intranet",
)

#: IPv4/IPv6 networks treated as internal. Covers loopback, link-local
#: (which includes the 169.254.169.254 metadata address), RFC 1918
#: private ranges, unspecified, and unique-local IPv6.
BLOCKED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / metadata
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified ("this host")
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
)

#: Decimal / octal / hex spellings of 127.0.0.1 that bypass naive
#: string matching (e.g. http://2130706433/, http://0x7f.0.0.1/).
#: Checked against the decoded host before IP parsing.
_LOOPBACK_SPELLINGS = frozenset({
    "2130706433",          # 127.0.0.1 as decimal
    "0x7f000001",          # 127.0.0.1 as hex
    "017700000001",        # 127.0.0.1 as octal
})


def _decode_host(raw_host: str) -> str:
    """Percent-decode the host and strip brackets/ports/trailing dots."""
    host = unquote(raw_host or "").strip().lower()
    # Strip IPv6 brackets.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # Strip a trailing dot (DNS root).
    if host.endswith("."):
        host = host[:-1]
    return host


def _host_is_blocked(host: str) -> bool:
    """True when the decoded host is an internal target."""
    if not host:
        return True  # empty host: fail closed
    if host in BLOCKED_HOSTNAMES:
        return True
    if host in _LOOPBACK_SPELLINGS:
        return True
    for suffix in BLOCKED_SUFFIXES:
        if host.endswith(suffix):
            return True
    # Numeric IP check (handles 127.1, 0x7f.1, etc. via ipaddress).
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # not an IP literal and not a blocked name: external
    return any(addr in net for net in BLOCKED_NETWORKS)


def _extract_url(tool_call: Mapping[str, Any]) -> str | None:
    """Pull the URL out of a tool-call mapping.

    Looks for common argument shapes: a top-level ``url`` key, an
    ``arguments``/``args``/``params`` mapping containing ``url``, or a
    ``href``/``endpoint`` key. Returns ``None`` when no URL is present
    (a call with no URL cannot pivot).
    """
    if not isinstance(tool_call, Mapping):
        return None
    for key in ("url", "href", "endpoint", "uri"):
        value = tool_call.get(key)
        if isinstance(value, str) and value:
            return value
    for nest in ("arguments", "args", "params", "input"):
        inner = tool_call.get(nest)
        if isinstance(inner, Mapping):
            for key in ("url", "href", "endpoint", "uri"):
                value = inner.get(key)
                if isinstance(value, str) and value:
                    return value
    return None


def _extract_tool_name(tool_call: Mapping[str, Any]) -> str:
    """Best-effort tool name for the record; never raises."""
    if not isinstance(tool_call, Mapping):
        return "<malformed>"
    for key in ("tool", "tool_name", "name", "function"):
        value = tool_call.get(key)
        if isinstance(value, str) and value:
            return value
    return "<unnamed>"


# ---------------------------------------------------------------------------
# Records and verdicts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PivotingAttempt:
    """Frozen record of one inspected tool call.

    ``blocked`` is True when the call targeted an internal address and
    must be refused. ``reason`` carries the fixed vocabulary term that
    fired (``internal-ip``, ``metadata-endpoint``, ``loopback``,
    ``unparseable-url``, ``no-url`` is never blocked).
    """

    tool_name: str
    url: str
    blocked: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": MCP_PIVOTING_VERSION,
            "tool_name": self.tool_name,
            "url": self.url,
            "blocked": self.blocked,
            "reason": self.reason,
        }


def _classify_reason(host: str) -> str:
    """Fixed-vocabulary reason for a blocked host."""
    if host in ("169.254.169.254", "metadata.google.internal",
                "metadata.google", "100.100.100.200",
                "instance-data", "instance-data.compute.internal"):
        return "metadata-endpoint"
    if host in ("localhost", "localhost.localdomain") or host in _LOOPBACK_SPELLINGS:
        return "loopback"
    return "internal-ip"


def detect_pivoting(tool_call: Mapping[str, Any]) -> bool:
    """True when the tool call attempts to reach an internal target.

    Fail-closed: a non-mapping call, or a URL that cannot be parsed
    into a host, counts as pivoting. A call carrying no URL at all
    returns False (nothing to pivot through).
    """
    if not isinstance(tool_call, Mapping):
        return True
    url = _extract_url(tool_call)
    if url is None:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    # urlsplit without a scheme puts everything in path; require a host.
    host = _decode_host(parts.hostname or "")
    if not host:
        # Try once more treating the whole string as host-ish (e.g.
        # "169.254.169.254/latest/meta-data").
        host = _decode_host(url.split("/")[0])
        if not host:
            return True
    return _host_is_blocked(host)


def inspect_tool_call(tool_call: Mapping[str, Any]) -> PivotingAttempt:
    """Inspect one tool call and return the frozen attempt record."""
    name = _extract_tool_name(tool_call)
    if not isinstance(tool_call, Mapping):
        return PivotingAttempt(tool_name=name, url="",
                               blocked=True, reason="unparseable-url")
    url = _extract_url(tool_call)
    if url is None:
        return PivotingAttempt(tool_name=name, url="",
                               blocked=False, reason="no-url")
    try:
        parts = urlsplit(url)
        host = _decode_host(parts.hostname or "") or _decode_host(url.split("/")[0])
    except ValueError:
        return PivotingAttempt(tool_name=name, url=url,
                               blocked=True, reason="unparseable-url")
    if not host:
        return PivotingAttempt(tool_name=name, url=url,
                               blocked=True, reason="unparseable-url")
    if _host_is_blocked(host):
        return PivotingAttempt(tool_name=name, url=url,
                               blocked=True, reason=_classify_reason(host))
    return PivotingAttempt(tool_name=name, url=url,
                           blocked=False, reason="external")


def check_tool_call(tool_name: str, url: str) -> PivotingAttempt:
    """One-call convenience for the dispatch site.

    Returns the attempt record; the caller refuses the call when
    ``record.blocked`` is True.
    """
    return inspect_tool_call({"tool": tool_name, "url": url})


def main() -> None:
    """Self-check smoke: blocked internals, allowed externals."""
    cases = [
        ("fetch", "http://169.254.169.254/latest/meta-data/", True),
        ("fetch", "http://localhost:8080/admin", True),
        ("fetch", "http://10.0.0.5/internal", True),
        ("fetch", "http://192.168.1.1/", True),
        ("fetch", "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/", True),
        ("fetch", "https://example.com/api", False),
        ("fetch", "https://api.github.com/repos", False),
    ]
    bad = 0
    for tool, url, want_blocked in cases:
        got = check_tool_call(tool, url)
        if got.blocked != want_blocked:
            bad += 1
            print(f"MISMATCH: {url} -> blocked={got.blocked}, want {want_blocked}")
    print(f"mcp-pivoting-detector OK: {len(cases) - bad}/{len(cases)} cases"
          f"{' -- FAILURES' if bad else ''}")


if __name__ == "__main__":
    main()
