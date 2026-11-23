"""Runtime defense 15: mTLS (client cert config), Simulated.

Mutual TLS config: client identity (cert path reference, never the key
material), allowed server CAs, and verification mode.  This is CONFIG
only -- private keys stay in the host key store / HSM, never in config.

What this IS: mTLS client config + policy validation.
What this IS NOT: key handling or TLS handshakes.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import FrozenSet, List

#: Module version.
RUNTIME_DEFENSE_15_VERSION = "runtime-defense-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-15.v1"


class MtlsError(Exception):
    """Fail-closed: bad mTLS config raises."""


@dataclass(frozen=True)
class MtlsConfig:
    """mTLS client configuration (references, not secrets)."""

    # Path/URI reference to the client cert in the host key store.
    # NEVER a PEM blob.
    client_cert_ref: str
    # Server CA names trusted for this connection.
    server_ca_names: FrozenSet[str]
    # Hosts this identity may present to.
    allowed_hosts: FrozenSet[str]
    # Verification mode: "strict" requires hostname + chain verification.
    verify_mode: str = "strict"
    min_tls_version: str = "1.2"

    def __post_init__(self):
        if not self.client_cert_ref:
            raise MtlsError("client_cert_ref required")
        if "BEGIN CERTIFICATE" in self.client_cert_ref:
            raise MtlsError(
                "client_cert_ref must be a reference, not PEM material"
            )
        if not self.server_ca_names:
            raise MtlsError("server_ca_names required: fail-closed")
        if not self.allowed_hosts:
            raise MtlsError("allowed_hosts required: fail-closed")
        if self.verify_mode not in ("strict",):
            raise MtlsError(
                f"verify_mode must be 'strict', got {self.verify_mode!r}"
            )
        if self.min_tls_version not in ("1.2", "1.3"):
            raise MtlsError(f"bad min_tls_version {self.min_tls_version!r}")

    def may_connect(self, host: str) -> bool:
        """Check host is in the allowed set (exact or wildcard)."""
        h = host.strip().lower().rstrip(".")
        for entry in self.allowed_hosts:
            if entry.startswith("*."):
                suffix = entry[2:]
                if h == suffix or h.endswith("." + suffix):
                    return True
            elif h == entry:
                return True
        return False


def build_config(
    client_cert_ref: str,
    server_ca_names: List[str],
    allowed_hosts: List[str],
) -> MtlsConfig:
    """Build mTLS config."""
    return MtlsConfig(
        client_cert_ref=client_cert_ref,
        server_ca_names=frozenset(server_ca_names),
        allowed_hosts=frozenset(
            h.strip().lower().rstrip(".") for h in allowed_hosts
        ),
    )


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    cfg = build_config(
        "keystore://agent/client-cert",
        ["Internal CA 2026"],
        ["api.example.com", "*.internal.example"],
    )
    assert cfg.verify_mode == "strict"
    assert cfg.may_connect("api.example.com") is True
    assert cfg.may_connect("svc.internal.example") is True
    assert cfg.may_connect("evil.com") is False

    # PEM material refused.
    try:
        build_config("-----BEGIN CERTIFICATE-----\n...", ["ca"], ["h"])
        raise AssertionError("should raise")
    except MtlsError:
        pass
    # Empty CA set refused.
    try:
        build_config("ref", [], ["h"])
        raise AssertionError("should raise")
    except MtlsError:
        pass
    # Non-strict verify refused.
    try:
        MtlsConfig(
            client_cert_ref="ref",
            server_ca_names=frozenset({"ca"}),
            allowed_hosts=frozenset({"h"}),
            verify_mode="none",
        )
        raise AssertionError("should raise")
    except MtlsError:
        pass

    assert stdlib_only()
    print("runtime-defense-15 OK: mtls config, no key material, stdlib")


if __name__ == "__main__":
    main()
