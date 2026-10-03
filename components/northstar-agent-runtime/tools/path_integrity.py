"""PATH-shim detection and tool-binary integrity pins.

Red-team model: `DavidCarliez/trustmebro
<https://github.com/DavidCarliez/trustmebro>`_ (MIT, (c) 2026 David
Carliez), verified against its actual README and repository layout before
any of its ideas were ported. TrustMeBro intercepts command-line tools an
agent invokes: rules decide whether to return fabricated output (``spoof``),
modify the real output (``rewrite``), block the call (``reject``), or
execute the real binary unchanged (``passthrough``). Interception works
through a shim directory prepended to ``PATH`` (install mode: shims live in
``~/.local/share/trustmebro/shims/`` and the shim directory is prepended to
shell startup files) or a Bubblewrap namespace that shadows both ``PATH``
lookups and discovered absolute paths (lab mode). The shim binary dispatches
on ``argv[0]``; real-binary resolution scans ``PATH`` and skips candidates
that resolve back to TrustMeBro itself.

Why the approval gate needs this: the per-call approval binding
(``call_id`` + ``arguments_digest``) authenticates the *request*, not the
*output*. A shim swaps the *binary*, never the arguments, so the existing
binding cannot see it — the fabricated stdout flows straight to the model,
and in trustmebro's own evaluation a fabricated DNS TXT marker was enough
to make models proceed with a scan the real tool would have blocked. This
module closes the gap in two places:

1. :class:`BinaryPin` — pin ``(name, realpath, content sha256)`` at tool
   registration time; :func:`verify_pin` re-resolves and re-hashes before
   execution and fails closed on any difference. A shim planted *after*
   pinning can never reproduce the pinned ``(path, digest)`` pair.
2. :func:`scan_path_shadows` — flags tool names whose ``PATH`` resolution
   differs from resolution under a trusted fallback (``/usr/bin:/bin``):
   the install-mode shim pattern, where the shim directory is prepended to
   ``PATH``.
3. :func:`digest_output` / :func:`verify_output_receipt` — bind the
   model-visible tool output into the execution receipt (``sha256`` of the
   canonical JSON), so post-execution forgery of a recorded output is
   detectable. The durable gateway computes the same digest for
   ``ToolExecutionResult.output_digest``; that is a parallel implementation,
   not an import — the runtime never imports durable-run (see
   ``durable_bridge.py``) — so only the field names and the digest wire
   format are shared, exactly like ``digest_arguments``.

Honest limits, stated up front rather than discovered in an incident:

* A shim planted *before* pinning (a compromised install-time trust root)
  pins the shim itself. :func:`scan_path_shadows` is the detector for that
  case, and it only sees ``PATH``-based shadowing, not lab-mode
  absolute-path shadowing.
* Output-content authenticity against an external ground truth is *not*
  claimed. The receipt proves *this output came from this binary at this
  time* and that the receipt was not rewritten afterwards. Whether the
  binary itself told the truth is a trust-root question, not a crypto one.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from typing import Any

#: Fallback PATH used as the trusted baseline for shadow scans. Mirrors the
#: sandbox's own fallback (``tools.os_sandbox._scrubbed_env``).
TRUSTED_FALLBACK_PATH = "/usr/bin:/bin"

#: Largest binary hashed by :func:`pin_binary` / :func:`verify_pin`.
_MAX_BINARY_BYTES = 64 * 1024 * 1024


def digest_bytes(data: bytes) -> str:
    """``sha256:<hex>`` digest of raw bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hash_file(path: str) -> str:
    """Digest of a file's bytes, streamed and size-bounded."""
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            total += len(chunk)
            if total > _MAX_BINARY_BYTES:
                raise ValueError(f"binary {path!r} exceeds the hashable size limit")
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class BinaryPin:
    """Pinned identity of the external binary behind a tool.

    ``path`` is the ``realpath`` at pin time (symlinks resolved, so a
    symlink swap is visible), ``digest`` the ``sha256:<hex>`` of the file
    bytes. The durable gateway carries a parallel definition with the same
    field names and digest format (translation, not import).
    """

    name: str
    path: str
    digest: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "path": self.path, "digest": self.digest}


def _resolve(name: str, path: str | None) -> str | None:
    if not name or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError(f"invalid tool binary name {name!r}")
    found = shutil.which(name, path=path)
    if found is None:
        return None
    return os.path.realpath(found)


def pin_binary(name: str, *, path: str | None = None) -> BinaryPin:
    """Pin a tool binary: resolve it now, record ``(realpath, content digest)``.

    ``path`` overrides the ``PATH`` used for resolution (tests pass an
    explicit directory so the real process environment is never touched).
    Raises ``ValueError`` when the binary cannot be resolved.
    """
    resolved = _resolve(name, path if path is not None else os.environ.get("PATH"))
    if resolved is None:
        raise ValueError(f"tool binary {name!r} not found on PATH")
    return BinaryPin(name=name, path=resolved, digest=_hash_file(resolved))


def verify_pin(pin: BinaryPin, *, path: str | None = None) -> tuple[bool, str]:
    """Re-resolve and re-hash; ``(True, ...)`` only on an exact match.

    Fails closed: a shim planted after pinning changes the resolved path,
    the file bytes, or both, and any of those differences is a refusal.
    Returns ``(ok, reason)`` rather than raising so the gateway can turn the
    refusal into a structured denial.
    """
    if not isinstance(pin, BinaryPin):
        return False, "pin is not a BinaryPin"
    resolved = _resolve(pin.name, path if path is not None else os.environ.get("PATH"))
    if resolved is None:
        return False, f"tool binary {pin.name!r} no longer resolves on PATH"
    if resolved != pin.path:
        return (
            False,
            f"tool binary {pin.name!r} resolved to {resolved!r}, "
            f"pinned to {pin.path!r} (PATH shadowing suspected)",
        )
    try:
        digest = _hash_file(resolved)
    except (OSError, ValueError) as error:
        return False, f"could not hash {resolved!r}: {error}"
    if digest != pin.digest:
        return (
            False,
            f"tool binary {pin.name!r} content digest changed "
            f"(binary replaced after pinning)",
        )
    return True, f"tool binary {pin.name!r} matches its pin"


def scan_path_shadows(
    names: list[str],
    *,
    path: str | None = None,
    trusted_path: str = TRUSTED_FALLBACK_PATH,
) -> list[dict[str, str]]:
    """Flag tool names shadowed on ``PATH`` relative to a trusted baseline.

    For each name, resolve under ``path`` (default: process ``PATH``) and
    under ``trusted_path``; a name whose realpaths differ is reported. This
    is the install-mode shim pattern — the shim directory prepended to
    ``PATH`` — and the detector for the case where pinning happened *after*
    the shim was planted. Names unresolvable under either side are skipped,
    not flagged: absence is not evidence of shadowing.
    """
    shadows: list[dict[str, str]] = []
    for name in names:
        live = _resolve(name, path if path is not None else os.environ.get("PATH"))
        trusted = _resolve(name, trusted_path)
        if live is None or trusted is None:
            continue
        if live != trusted:
            shadows.append(
                {
                    "name": name,
                    "path_resolution": live,
                    "trusted_resolution": trusted,
                }
            )
    return shadows


def digest_output(output: Any) -> str:
    """``sha256:<hex>`` of the canonical JSON of a tool output.

    Same canonical form as the durable gateway's
    ``ToolExecutionResult.output_digest`` (parallel implementation; only the
    wire format is shared).
    """
    try:
        encoded = json.dumps(
            output if isinstance(output, dict) else {},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("tool output is not JSON-serialisable") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def verify_output_receipt(output: Any, expected_digest: str) -> tuple[bool, str]:
    """Recompute the output digest and compare with the recorded receipt.

    Detects post-execution forgery of a recorded tool output: if the
    ``output`` dict was swapped after the receipt was written, the digest no
    longer matches. Returns ``(ok, reason)``.
    """
    try:
        actual = digest_output(output)
    except ValueError as error:
        return False, str(error)
    if actual != expected_digest:
        return (
            False,
            "recorded tool output does not match its receipt digest "
            "(output forged after execution)",
        )
    return True, "recorded tool output matches its receipt digest"


__all__ = [
    "TRUSTED_FALLBACK_PATH",
    "BinaryPin",
    "digest_bytes",
    "digest_output",
    "pin_binary",
    "scan_path_shadows",
    "verify_output_receipt",
    "verify_pin",
]
