"""One source of truth for the runtime → sidecar wire format, checked against the Run Contract.

Why this module exists
----------------------
The sidecar's request schema is three fields (``request_id``, ``prompt``,
``timeout_ms``). Before this module the runtime kept its **own copy** of that
schema and its own validator, while ``northstar-run-contract`` defined the
governed version of the same boundary (a validated Run Request, an expiring HMAC
Run Binding, and :func:`adapter.to_sidecar_request`, which narrows a verified run
to exactly those three fields). Two definitions of one boundary drift, and the
governance story ("every execution is attributable to an authorized run") had a
hole at precisely the seam where policy leaves the process.

What this module does
---------------------
1. :func:`derive_request_id` makes the run's ``run_id`` the sidecar
   ``request_id`` when the operator supplied one, so the runtime audit stream,
   the sidecar log, and a host Run Binding share one correlation key.
2. :func:`cross_check` re-derives the request from the contract path
   (``validate_run_request`` → ``verify_binding`` → ``to_sidecar_request``) and
   refuses the call if the two derivations disagree. It is **opt-in**: with no
   contract importable and no host key in the environment it reports
   ``unchecked`` and changes nothing, because the runtime must stay
   importable on a bare interpreter.
3. ``tests/test_contract_bridge.py`` pins the three-way agreement (runtime ↔
   contract adapter ↔ sidecar validator), so a future edit to any one of them
   fails a test instead of silently splitting the format.

Deliberate limit (stated, not hidden)
-------------------------------------
The sidecar still authenticates callers through Unix permissions only: it holds
no host key, so it cannot verify a binding itself. Wiring a binding onto the
*wire* is a protocol change to a security-sensitive component (its request field
allowlist is exactly what makes it refuse capabilities) and is left as an
explicit decision for the maintainers; see
``docs/benchmark-top-agents-2026-09.zh-CN.md`` F1.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Mapping

#: The complete legacy sidecar boundary. Mirrored from
#: ``northstar-run-contract/adapter.py::to_sidecar_request``; the test suite pins
#: both sides, plus the sidecar's own allowlist, to this one tuple.
WIRE_FIELDS: frozenset[str] = frozenset({"request_id", "prompt", "timeout_ms"})

#: The sidecar rejects a longer id, and a correlation key that cannot survive
#: being embedded in a log line or a filename is not a correlation key.
MAX_REQUEST_ID_CHARS = 128

#: The run contract's id rule (``contract._ID_RE``): no whitespace, no slashes.
ID_RE = re.compile(r"^[^\s/\\]+$")

#: Environment seam for a host that mints Run Bindings (see northstar-host).
BINDING_ENV = "NORTHSTAR_RUN_BINDING"
HOST_KEY_ENV = "NORTHSTAR_HOST_KEY"
#: Path to the JSON Run Request document the binding was minted for.
RUN_REQUEST_ENV = "NORTHSTAR_RUN_REQUEST"

LEGACY_PREFIX = "nsar"


class BridgeError(ValueError):
    """A run id or binding that cannot be used. Reported to the operator."""


@dataclass(frozen=True)
class BridgeReport:
    """What the bridge concluded about one request. ``ok`` is the only verdict loop code reads."""

    mode: str = "unchecked"  # "unchecked" | "contract-verified" | "unavailable"
    ok: bool = True
    errors: tuple[str, ...] = ()
    detail: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": self.mode, "ok": self.ok}
        if self.errors:
            payload["errors"] = list(self.errors)
        if self.detail:
            payload["detail"] = dict(self.detail)
        return payload


def derive_request_id(run_id: str | None, *, prefix: str = LEGACY_PREFIX) -> str:
    """Return the sidecar ``request_id`` for one run.

    A supplied ``run_id`` is used verbatim: that is the whole point (the runtime
    and the sidecar then agree on one key). An absent id keeps the historical
    generated form so unconfigured behaviour is unchanged.
    """
    if run_id is None or run_id == "":
        return f"{prefix}-{_uuid_suffix()}"
    value = str(run_id).strip()
    if not value:
        raise BridgeError("run_id must not be blank")
    if len(value) > MAX_REQUEST_ID_CHARS:
        raise BridgeError(f"run_id must be at most {MAX_REQUEST_ID_CHARS} characters")
    if not ID_RE.match(value):
        raise BridgeError("run_id must contain no whitespace and no '/' or '\\\\' characters")
    return value


def _uuid_suffix() -> str:
    import uuid

    return uuid.uuid4().hex[:16]


def contract_available() -> bool:
    """True when the Run Contract modules are importable *and* recognisable.

    The module names are generic, so an attribute probe is required: a host with
    an unrelated ``contract`` module must not be mistaken for the run contract.
    """
    try:
        import adapter  # type: ignore

        return callable(getattr(adapter, "to_sidecar_request", None))
    except Exception:  # noqa: BLE001 - any import failure means "not the contract"
        return False


def binding_from_environment() -> tuple[str, bytes] | None:
    """Return ``(token, secret)`` when the host injected both, else ``None``.

    The secret is read as hex text from ``NORTHSTAR_HOST_KEY``; a path form is
    deliberately not supported so a stray file cannot be mistaken for a key.
    """
    token = os.environ.get(BINDING_ENV, "").strip()
    secret_text = os.environ.get(HOST_KEY_ENV, "").strip()
    if not token or not secret_text:
        return None
    try:
        secret = bytes.fromhex(secret_text)
    except ValueError as error:
        raise BridgeError(f"{HOST_KEY_ENV} must be hex-encoded bytes") from error
    if not secret:
        raise BridgeError(f"{HOST_KEY_ENV} must not be empty")
    return token, secret


def run_document_from_environment() -> dict[str, Any] | None:
    """Load the Run Request document named by ``NORTHSTAR_RUN_REQUEST``.

    The file must be a JSON object and must not be a symlink: a host that hands
    the runtime a binding to verify should not be able to be tricked into
    verifying a document the *agent* placed. Anything unreadable is reported as
    "no document", which fails the cross-check closed.
    """
    raw_path = os.environ.get(RUN_REQUEST_ENV, "").strip()
    if not raw_path:
        return None
    path = os.path.realpath(raw_path)
    if path != os.path.abspath(raw_path):
        raise BridgeError(f"{RUN_REQUEST_ENV} must not be a symlink")
    try:
        import json

        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as error:
        raise BridgeError(f"{RUN_REQUEST_ENV} cannot be read: {error}") from error
    except ValueError as error:
        raise BridgeError(f"{RUN_REQUEST_ENV} is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise BridgeError(f"{RUN_REQUEST_ENV} must hold a JSON object")
    return document


def cross_check(request: Mapping[str, Any], *, run: Mapping[str, Any] | None = None) -> BridgeReport:
    """Re-derive ``request`` through the contract and require agreement.

    ``run`` is the operator-supplied Run Request document (see
    ``northstar-run-contract``). Without a binding in the environment there is
    nothing to verify, so the report says ``unchecked`` rather than pretending.
    """
    keys = frozenset(request)
    if keys != WIRE_FIELDS:
        return BridgeReport(mode="unavailable", ok=False, errors=(f"request fields must be exactly {sorted(WIRE_FIELDS)}",))
    credentials = binding_from_environment()
    if credentials is None:
        return BridgeReport(mode="unchecked")
    token, secret = credentials
    if not contract_available():
        # A host key was provided but the contract is not importable: refusing is
        # the only honest option, because "we could not verify" is not "verified".
        return BridgeReport(
            mode="unavailable",
            ok=False,
            errors=(f"{BINDING_ENV} is set but northstar-run-contract is not importable; refusing an unverifiable run",),
        )
    if run is None:
        try:
            run = run_document_from_environment()
        except BridgeError as error:
            return BridgeReport(mode="contract-verified", ok=False, errors=(str(error),))
    if run is None:
        return BridgeReport(mode="contract-verified", ok=False, errors=("no Run Request document was supplied to verify against",))
    import adapter  # type: ignore
    import binding as binding_module  # type: ignore
    import contract as contract_module  # type: ignore
    import time

    validation = contract_module.validate_run_request(dict(run))
    if not validation.ok:
        return BridgeReport(mode="contract-verified", ok=False, errors=tuple(f"run request: {e}" for e in validation.errors))
    verified = binding_module.verify_binding(token, secret, now=int(time.time()))
    if not verified.ok:
        return BridgeReport(mode="contract-verified", ok=False, errors=tuple(f"binding: {e}" for e in verified.errors))
    try:
        expected = adapter.to_sidecar_request(dict(run), verified)
    except Exception as error:  # noqa: BLE001 - surfaced as a denial, never a crash
        return BridgeReport(mode="contract-verified", ok=False, errors=(f"adapter: {error}",))
    mismatches = sorted(
        f"{name}: runtime={request.get(name)!r} contract={expected.get(name)!r}"
        for name in sorted(WIRE_FIELDS)
        if request.get(name) != expected.get(name)
    )
    if mismatches:
        return BridgeReport(mode="contract-verified", ok=False, errors=tuple(mismatches))
    return BridgeReport(
        mode="contract-verified",
        detail={"run_id": run.get("run_id"), "actor_id": run.get("actor_id"), "workspace_id": run.get("workspace_id")},
    )


def build_request(prompt: str, *, run_id: str | None, timeout_ms: int) -> dict[str, Any]:
    """The one place a sidecar request is constructed."""
    return {"request_id": derive_request_id(run_id), "prompt": prompt, "timeout_ms": timeout_ms}


__all__ = [
    "BINDING_ENV",
    "HOST_KEY_ENV",
    "MAX_REQUEST_ID_CHARS",
    "WIRE_FIELDS",
    "BridgeError",
    "BridgeReport",
    "binding_from_environment",
    "build_request",
    "RUN_REQUEST_ENV",
    "contract_available",
    "cross_check",
    "run_document_from_environment",
    "derive_request_id",
]
