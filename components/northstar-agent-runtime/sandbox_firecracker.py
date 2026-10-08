"""Firecracker microVM config generator (config/policy layer only), Simulated.

Generates and validates Firecracker microVM configurations:
vcpu/memory, kernel boot, rootfs drives, network interfaces, vsock.

Does NOT launch microVMs.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
FIRECRACKER_VERSION = "sandbox-firecracker.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-firecracker.v1"


class FirecrackerError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class DriveConfig:
    drive_id: str
    path_on_host: str
    is_root_device: bool = False
    is_read_only: bool = True


@dataclass
class NetIfaceConfig:
    iface_id: str
    host_dev_name: str
    allow_mmds_requests: bool = False


@dataclass
class FirecrackerConfig:
    """Firecracker microVM configuration."""

    vcpu_count: int = 1
    mem_size_mib: int = 256
    kernel_image_path: str = "/opt/fc/vmlinux"
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    drives: List[DriveConfig] = field(default_factory=list)
    network_interfaces: List[NetIfaceConfig] = field(default_factory=list)
    vsock_enabled: bool = False
    # No network by default = isolated.
    enable_networking: bool = False


def generate_config(
    rootfs: str,
    *,
    enable_networking: bool = False,
    **overrides: Any,
) -> FirecrackerConfig:
    """Generate a locked-down microVM config."""
    if not rootfs:
        raise FirecrackerError("rootfs path required")
    cfg = FirecrackerConfig(enable_networking=enable_networking)
    cfg.drives = [
        DriveConfig(
            drive_id="rootfs",
            path_on_host=rootfs,
            is_root_device=True,
            is_read_only=True,  # rootfs always read-only
        )
    ]
    if enable_networking:
        cfg.network_interfaces = [
            NetIfaceConfig(iface_id="eth0", host_dev_name="tap0")
        ]
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise FirecrackerError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    validate_config(cfg)
    return cfg


def validate_config(cfg: FirecrackerConfig) -> None:
    """Validate.  Raises FirecrackerError."""
    if not isinstance(cfg, FirecrackerConfig):
        raise FirecrackerError("cfg must be FirecrackerConfig")
    if cfg.vcpu_count < 1 or cfg.vcpu_count > 32:
        raise FirecrackerError("vcpu_count out of range")
    if cfg.mem_size_mib < 128 or cfg.mem_size_mib > 16384:
        raise FirecrackerError("mem_size_mib out of range")
    if not cfg.kernel_image_path:
        raise FirecrackerError("kernel_image_path required")
    if not cfg.drives:
        raise FirecrackerError("at least one drive required")
    # Root device must be read-only.
    for drive in cfg.drives:
        if drive.is_root_device and not drive.is_read_only:
            raise FirecrackerError("root device must be read-only")
        if not drive.path_on_host:
            raise FirecrackerError("drive path required")
    # Network consistency.
    if cfg.enable_networking and not cfg.network_interfaces:
        raise FirecrackerError("networking enabled but no interfaces")
    if not cfg.enable_networking and cfg.network_interfaces:
        raise FirecrackerError("interfaces defined but networking disabled")


def to_api_payload(cfg: FirecrackerConfig) -> Dict[str, Any]:
    """Render as Firecracker REST API payload (not sent)."""
    validate_config(cfg)
    return {
        "machine-config": {
            "vcpu_count": cfg.vcpu_count,
            "mem_size_mib": cfg.mem_size_mib,
        },
        "boot-source": {
            "kernel_image_path": cfg.kernel_image_path,
            "boot_args": cfg.boot_args,
        },
        "drives": [
            {
                "drive_id": d.drive_id,
                "path_on_host": d.path_on_host,
                "is_root_device": d.is_root_device,
                "is_read_only": d.is_read_only,
            }
            for d in cfg.drives
        ],
        "network-interfaces": [
            {
                "iface_id": n.iface_id,
                "host_dev_name": n.host_dev_name,
                "allow_mmds_requests": n.allow_mmds_requests,
            }
            for n in cfg.network_interfaces
        ],
    }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    cfg = generate_config("/opt/fc/rootfs.ext4")
    assert cfg.drives[0].is_read_only is True
    payload = to_api_payload(cfg)
    assert payload["machine-config"]["vcpu_count"] == 1
    bad = FirecrackerConfig()
    bad.drives = [DriveConfig("r", "/x", is_root_device=True, is_read_only=False)]
    try:
        validate_config(bad)
        raise AssertionError("should raise")
    except FirecrackerError:
        pass
    assert stdlib_only()
    print("sandbox-firecracker OK")


if __name__ == "__main__":
    main()
