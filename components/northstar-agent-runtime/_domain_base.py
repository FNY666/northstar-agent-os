"""Shared base for the 39 domain packs.

Each ``*_agents.py`` domain module defines its own ``XxxError`` for
backward compatibility (callers catch the specific name), but they all
share this base so hosts can also catch every domain-pack error with a
single ``except DomainError``.
"""


class DomainError(ValueError):
    """Base for all domain-pack errors.

    A malformed receipt, registry, or request — a programming error,
    not a verdict. Verification *failures* (unknown authority, bad
    signature, expired grant) are returned as verdicts, not raised.
    """
