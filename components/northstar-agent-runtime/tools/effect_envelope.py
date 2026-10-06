"""Effect Envelope: unified path containment (Orrery Gate 2 style).

Orrery's Gate 2 requires every target path to be canonicalized and fall
within an authorized subtree, defending against ``../``, null bytes, and
symlink escapes. Northstar previously had six ad-hoc containment checks
(agent_files, policy_file, skills, mcp_config, command_hooks, plus
path_integrity for binaries) with varying strictness and zero null-byte
checks.

This module is the single Effect Envelope: one function, one strictness.
Callsites should migrate to it; the audit
(``hidden_files/effect-envelope-audit-20261006.md``) tracks migration.

Checks, in order:
1. Null bytes: rejected explicitly (Orrery Gate 2 names this; Python's
   ``pathlib`` behavior on ``\\x00`` varies by version and call, so we
   don't rely on it).
2. Absolute paths: rejected unless ``allow_absolute`` -- the envelope is
   workspace-relative by default.
3. ``..`` components: rejected lexically before resolution (defense in
   depth; resolution would also collapse them, but explicit is auditable).
4. Canonicalization: both root and target are ``realpath``'d (symlinks
   resolved), then containment is checked via ``is_relative_to``.
5. Symlinks: optionally rejected entirely (``reject_symlinks``); when
   allowed, the resolved target must still be inside the root.

TOCTOU note: this checks the path at call time. A symlink swapped between
check and use is a TOCTOU race; ``reject_symlinks=True`` closes it for
callers that don't need symlink support. Callers that open the file
immediately after should prefer ``os.open`` with ``O_NOFOLLOW`` where the
platform supports it.
"""

from __future__ import annotations

import os
from pathlib import Path


class EffectEnvelopeError(ValueError):
    """A path violates the Effect Envelope."""


def contain(
    raw: str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    allow_absolute: bool = False,
    reject_symlinks: bool = False,
) -> Path:
    """Resolve ``raw`` against ``root`` and enforce the Effect Envelope.

    Returns the canonical (realpath'd) target inside ``root``.
    Raises :class:`EffectEnvelopeError` on any violation.
    """
    if isinstance(raw, os.PathLike):
        raw = os.fspath(raw)
    if not isinstance(raw, str):
        raise EffectEnvelopeError(f"path must be str, not {type(raw).__name__}")
    if "\x00" in raw:
        raise EffectEnvelopeError(f"path contains null byte: {raw!r}")
    text = raw.strip()
    if not text:
        raise EffectEnvelopeError("path must not be empty")
    candidate = Path(text)
    if candidate.is_absolute() and not allow_absolute:
        raise EffectEnvelopeError(f"path must be workspace-relative, not absolute: {raw!r}")
    if ".." in candidate.parts:
        raise EffectEnvelopeError(f"path must not contain '..': {raw!r}")

    root_real = Path(os.path.realpath(os.fspath(root)))
    if candidate.is_absolute():
        target = Path(os.path.realpath(text))
    else:
        target = Path(os.path.realpath(str(root_real / candidate)))
    try:
        target.relative_to(root_real)
    except ValueError:
        raise EffectEnvelopeError(
            f"path {raw!r} resolves outside the workspace root {root_real}"
        ) from None
    if reject_symlinks:
        # Check both the pre-resolution join and the resolved target: a
        # symlink anywhere in the chain is refused.
        joined = root_real / candidate if not candidate.is_absolute() else Path(text)
        if joined.is_symlink() or target.is_symlink():
            raise EffectEnvelopeError(f"path must not be a symlink: {raw!r}")
    return target


__all__ = ["EffectEnvelopeError", "contain"]
