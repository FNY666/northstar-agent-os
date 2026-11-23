"""WASM (wasmtime) capability config (config/policy layer only), Simulated.

Generates and validates WebAssembly sandbox capability configurations:
fuel limits, memory caps, WASI capability allowlists (no network by
default), allowed host imports.

Does NOT execute WASM.  Config/policy layer only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
WASM_VERSION = "sandbox-wasm.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sandbox-wasm.v1"


class WasmError(Exception):
    """Fail-closed: invalid configs raise."""


@dataclass
class WasmConfig:
    """wasmtime sandbox configuration."""

    module_path: str
    # Fuel: instruction budget (None = unlimited, forbidden here).
    fuel: int = 10_000_000
    # Memory limits.
    max_memory_bytes: int = 64 * 1024 * 1024  # 64MB
    max_table_elements: int = 10000
    # WASI capabilities.
    allow_stdin: bool = False
    allow_stdout: bool = True
    allow_stderr: bool = True
    allow_network: bool = False
    allow_random: bool = True
    allow_clocks: bool = True
    # Preopened dirs (capability-style): guest_path -> host_path.
    preopened_dirs: Dict[str, str] = field(default_factory=dict)
    # Allowed host function imports (explicit allowlist).
    allowed_imports: List[str] = field(default_factory=list)


def generate_config(
    module_path: str,
    *,
    preopened_dirs: Dict[str, str] = None,
    **overrides: Any,
) -> WasmConfig:
    """Generate a locked-down wasmtime config."""
    if not module_path:
        raise WasmError("module_path required")
    cfg = WasmConfig(
        module_path=module_path,
        preopened_dirs=dict(preopened_dirs or {}),
    )
    for key, value in overrides.items():
        if not hasattr(cfg, key):
            raise WasmError(f"unknown config key '{key}'")
        setattr(cfg, key, value)
    # Enforce invariants.
    cfg.allow_network = False
    validate_config(cfg)
    return cfg


def validate_config(cfg: WasmConfig) -> None:
    """Validate.  Raises WasmError."""
    if not isinstance(cfg, WasmConfig):
        raise WasmError("cfg must be WasmConfig")
    if not cfg.module_path:
        raise WasmError("module_path required")
    if cfg.fuel is None or cfg.fuel <= 0:
        raise WasmError("fuel must be a positive integer (no unlimited)")
    if cfg.fuel > 1_000_000_000:
        raise WasmError("fuel exceeds maximum")
    if cfg.max_memory_bytes <= 0 or cfg.max_memory_bytes > 1024**3:
        raise WasmError("max_memory_bytes out of range")
    if cfg.allow_network:
        raise WasmError("network capability is forbidden")
    # Preopened dirs must not escape to sensitive host paths.
    for guest, host in cfg.preopened_dirs.items():
        if host in ("/", "/etc", "/root", "/proc", "/sys"):
            raise WasmError(f"sensitive host path '{host}' in preopened_dirs")
        if ".." in host or ".." in guest:
            raise WasmError("path traversal in preopened_dirs")


def to_wasmtime_args(cfg: WasmConfig) -> List[str]:
    """Render as wasmtime CLI args (not executed)."""
    validate_config(cfg)
    args = [
        "wasmtime", "run",
        f"--fuel={cfg.fuel}",
        f"--max-memory-size={cfg.max_memory_bytes}",
    ]
    for guest, host in cfg.preopened_dirs.items():
        args += ["--dir", f"{host}::{guest}"]
    if not cfg.allow_stdin:
        args += ["--stdin=/dev/null"]
    args += [cfg.module_path]
    return args


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
    cfg = generate_config("/tmp/mod.wasm", preopened_dirs={"/work": "/workspace"})
    assert cfg.allow_network is False
    args = to_wasmtime_args(cfg)
    assert "--fuel=10000000" in args
    try:
        bad = WasmConfig(module_path="/x", fuel=None)
        validate_config(bad)
        raise AssertionError("should raise")
    except WasmError:
        pass
    assert stdlib_only()
    print("sandbox-wasm OK")


if __name__ == "__main__":
    main()
