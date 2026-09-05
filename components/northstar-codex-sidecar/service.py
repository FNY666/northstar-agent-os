"""Static safety contract for the Codex sidecar service."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import PurePosixPath

SOCKET_ROOT = PurePosixPath("/var/run/northstar-codex")

@dataclass(frozen=True)
class ServiceValidation:
    ok: bool
    errors: tuple[str, ...] = ()

def validate_socket_path(value: str) -> ServiceValidation:
    path = PurePosixPath(value)
    if not value.startswith(str(SOCKET_ROOT) + "/"):
        return ServiceValidation(False, ("socket must be below private sidecar runtime directory",))
    if path.name != "sidecar.sock":
        return ServiceValidation(False, ("socket filename must be sidecar.sock",))
    return ServiceValidation(True)

def service_config() -> dict[str, object]:
    return {
        "user": "northstar-codex",
        "group": "northstar-codex",
        "sandbox": "read-only",
        "native_tools": False,
        "transport": "unix",
        "socket": str(SOCKET_ROOT / "sidecar.sock"),
        "codex_bin": "codex",
        "stop_timeout_seconds": 15,
        "runtime_directory": "northstar-codex",
        "runtime_directory_mode": "0770",
    }
