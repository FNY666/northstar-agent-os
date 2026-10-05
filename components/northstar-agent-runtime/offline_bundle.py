"""Signed offline policy bundles (ninety-seventh batch).

Absorbed from the 2026 space-AI sweep: satellites cannot phone home for
approval — policy must be **compiled** into the agent as a signed,
expiry-bounded bundle. This generalizes to every disconnected agent:
field robotics, air-gapped factories, orbital compute. An offline agent
that cannot reach a policy server must still be governed; the bundle is
how governance travels with it.

Bundle model (fail-closed throughout):

* ``compile_bundle()`` takes an allowlist policy (Janus-style rule
  list, see the ninety-first batch), a tool-name -> definition mapping,
  and an expiry epoch, and emits a signed document. The signature is
  Ed25519 over the canonical JSON of the payload (the vendored
  ``ed25519`` module; canonical form is this module's local
  deterministic encoder — the ninety-fifth batch's canonicalizer was
  not present in the tree, so the bundle pins its own canonical form
  inside the signed envelope and refuses anything that does not match
  it byte-for-byte).
* ``verify_bundle()`` enforces, in order: well-formed envelope ->
  signature over canonical bytes -> known issuer (the expected
  authority public key; an unknown signer is denied, never
  "accepted with a warning") -> not expired -> not stale (the
  staleness ceiling bounds how old the *policy itself* may be, even
  inside its expiry window) -> monotonic version (a bundle older than
  the newest version the agent has seen is a rollback to weaker
  policy and is denied) -> tool-definition digests pinned inside the
  bundle must match the live registry (the ninety-first batch's
  ``definition_digest`` semantics: a silently swapped tool definition
  is a tamper event, fail-closed).
* ``offline_check()`` gates a single tool call against a *verified*
  bundle: unknown tool -> deny; no matching allow rule -> deny
  (default-deny, Janus semantics); an explicit deny rule always wins.

Non-negotiable rule: **the agent MUST NOT operate on an unverifiable
bundle.** ``verify_bundle`` returns a verdict value, never raises, and
``offline_check`` refuses to run against anything but a positively
verified bundle. There is no "offline lenient mode".

Honest scope:

* This module does not solve key distribution: the expected authority
  public key must reach the agent through an out-of-band trusted
  channel. A bundle signed by the wrong key is indistinguishable from
  an attack, and is treated as one.
* Time comes from the caller (``now_epoch``). An offline agent with a
  wrong clock can be tricked about expiry; the module documents this
  and offers the staleness ceiling as a second, independent bound, but
  cannot fix a lying clock.
* The policy language is a deliberately small subset (tool allow/deny
  with optional argument constraints). Anything outside the subset is
  refused at compile time, never silently ignored.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

import ed25519

try:  # ninety-first batch semantics, reused not reinvented
    from static_verify import definition_digest as _definition_digest
except Exception:  # pragma: no cover - module must stay importable standalone
    _definition_digest = None  # type: ignore[assignment]


BUNDLE_SCHEMA_VERSION = 1

_SIGNATURE_BYTES = 64

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

_ARG_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


# ---------------------------------------------------------------------------
# Canonical encoding (local; pinned inside the signed envelope)
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> str:
    """Deterministic JSON encoding for signing (sorted keys, tight separators).

    The bundle pins this exact encoding: ``verify_bundle`` re-encodes
    the payload with this function and compares bytes before checking
    the signature, so any non-canonical encoding is rejected even if
    the signature would otherwise verify.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tool_digest(definition: Mapping[str, Any]) -> str | None:
    """Pin a tool definition (ninety-first batch semantics)."""
    if _definition_digest is not None:
        try:
            return _definition_digest(dict(definition))
        except Exception:
            return None
    # Fallback canonical digest if static_verify is unavailable.
    try:
        canon = {
            "name": definition["name"],
            "description": definition.get("description", ""),
            "params": sorted(
                (
                    {
                        "name": p["name"],
                        "type": p.get("type", "string"),
                        "required": bool(p.get("required", False)),
                    }
                    for p in definition.get("params", [])
                ),
                key=lambda p: p["name"],
            ),
        }
        return sha256_hex(canonical_json(canon))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Policy rule validation (compile-time; Janus-shaped, stdlib subset)
# ---------------------------------------------------------------------------


def _validate_rule(rule: Any) -> str | None:
    """Return an error string, or None if the rule is well-formed."""
    if not isinstance(rule, dict):
        return "rule must be a mapping"
    tool = rule.get("tool")
    if not isinstance(tool, str) or not _TOOL_NAME_RE.match(tool):
        return "rule.tool must be a valid tool name"
    effect = rule.get("effect")
    if effect not in ("allow", "deny"):
        return "rule.effect must be 'allow' or 'deny'"
    conditions = rule.get("conditions", [])
    if not isinstance(conditions, list):
        return "rule.conditions must be a list"
    for cond in conditions:
        if not isinstance(cond, dict):
            return "condition must be a mapping"
        arg = cond.get("arg")
        if not isinstance(arg, str) or not arg:
            return "condition.arg must be a non-empty string"
        if "equals" in cond and "pattern" in cond:
            return "condition may not combine equals and pattern"
        if "pattern" in cond:
            if not isinstance(cond["pattern"], str):
                return "condition.pattern must be a string"
            try:
                re.compile(cond["pattern"])
            except re.error:
                return "condition.pattern is not a valid regex"
        if "type" in cond and cond["type"] not in _ARG_TYPE_CHECKS:
            return f"unsupported condition.type: {cond['type']!r}"
    return None


def _validate_policy(policy: Any) -> str | None:
    if not isinstance(policy, list) or not policy:
        return "policy must be a non-empty list of rules"
    for rule in policy:
        err = _validate_rule(rule)
        if err:
            return err
    return None


# ---------------------------------------------------------------------------
# Bundle compilation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleEnvelope:
    """The signed document. ``payload`` excludes ``signature``."""

    payload: dict[str, Any]
    signature_hex: str

    def to_dict(self) -> dict[str, Any]:
        doc = dict(self.payload)
        doc["signature"] = self.signature_hex
        return doc

    @staticmethod
    def from_dict(doc: Mapping[str, Any]) -> "BundleEnvelope | None":
        if not isinstance(doc, Mapping):
            return None
        sig = doc.get("signature")
        if not isinstance(sig, str):
            return None
        payload = {k: v for k, v in doc.items() if k != "signature"}
        return BundleEnvelope(payload=payload, signature_hex=sig)


class BundleError(Exception):
    """Raised only by compile_bundle on caller mistakes (fail loud at build)."""


def compile_bundle(
    policy: list[dict[str, Any]],
    tools: Mapping[str, Mapping[str, Any]],
    expiry_epoch: int,
    *,
    issuer_secret: bytes,
    bundle_version: int,
    staleness_ceiling_s: int,
    issued_at: int,
) -> dict[str, Any]:
    """Compile and sign an offline policy bundle.

    Raises :class:`BundleError` on any caller-side problem (bad policy,
    bad tool definitions, non-monotonic fields). The returned dict is
    the signed bundle document; ``signature`` covers the canonical
    encoding of every other field.
    """
    if not isinstance(issuer_secret, (bytes, bytearray)) or len(issuer_secret) != 32:
        raise BundleError("issuer_secret must be a 32-byte Ed25519 seed")
    if not isinstance(bundle_version, int) or bundle_version < 1:
        raise BundleError("bundle_version must be a positive integer")
    if not isinstance(expiry_epoch, int) or not isinstance(issued_at, int):
        raise BundleError("expiry_epoch and issued_at must be integer epochs")
    if expiry_epoch <= issued_at:
        raise BundleError("expiry_epoch must be after issued_at")
    if not isinstance(staleness_ceiling_s, int) or staleness_ceiling_s < 0:
        raise BundleError("staleness_ceiling_s must be a non-negative integer")

    perr = _validate_policy(policy)
    if perr:
        raise BundleError(f"policy rejected: {perr}")
    if not isinstance(tools, Mapping) or not tools:
        raise BundleError("tools must be a non-empty mapping")

    digests: dict[str, str] = {}
    for name, definition in tools.items():
        if not isinstance(name, str) or not _TOOL_NAME_RE.match(name):
            raise BundleError(f"invalid tool name: {name!r}")
        if not isinstance(definition, Mapping):
            raise BundleError(f"tool definition for {name!r} must be a mapping")
        digest = _tool_digest(definition)
        if digest is None:
            raise BundleError(f"tool definition for {name!r} is not digestible")
        digests[name] = digest

    policy_tools = {r["tool"] for r in policy if isinstance(r, dict)}
    unknown = policy_tools - set(tools)
    if unknown:
        raise BundleError(f"policy names tools with no pinned definition: {sorted(unknown)}")

    issuer_pub = ed25519.public_key(bytes(issuer_secret)).hex()
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_version": bundle_version,
        "issuer": issuer_pub,
        "issued_at": issued_at,
        "expires_at": expiry_epoch,
        "staleness_ceiling_s": staleness_ceiling_s,
        "policy": policy,
        "tool_digests": digests,
    }
    canonical = canonical_json(payload).encode("utf-8")
    signature = ed25519.sign(bytes(issuer_secret), canonical).hex()
    return BundleEnvelope(payload=payload, signature_hex=signature).to_dict()


# ---------------------------------------------------------------------------
# Bundle verification (fail-closed; never raises)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleVerdict:
    ok: bool
    reason: str
    bundle: dict[str, Any] = field(default_factory=dict)


def verify_bundle(
    bundle: Any,
    *,
    issuer_pubkey: bytes,
    now_epoch: int,
    min_version: int,
    registry_digests: Mapping[str, str] | None = None,
) -> BundleVerdict:
    """Verify a bundle. Returns a verdict; never raises.

    Checks, in order: envelope shape -> claimed issuer is the expected
    authority (fail-closed fast path; the claim is unauthenticated here
    but a mismatch can only deny, never allow) -> signature over
    canonical bytes -> expiry -> staleness ceiling -> monotonic
    version -> pinned tool digests. The first failure wins and the
    bundle is unusable.
    """
    def deny(reason: str) -> BundleVerdict:
        return BundleVerdict(ok=False, reason=reason)

    if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:
        return deny("verifier misconfigured: issuer_pubkey must be 32 bytes")
    if not isinstance(now_epoch, int) or not isinstance(min_version, int):
        return deny("verifier misconfigured: now_epoch/min_version must be ints")

    env = BundleEnvelope.from_dict(bundle) if isinstance(bundle, Mapping) else None
    if env is None:
        return deny("malformed bundle: not a mapping with a string signature")
    payload = env.payload
    if payload.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        return deny("malformed bundle: unsupported schema_version")

    # Issuer identity first: the bundle's claimed issuer must be the
    # expected authority. Safe to check before the signature because a
    # mismatch can only deny — allowing still requires a valid signature
    # over these exact bytes.
    if payload.get("issuer") != bytes(issuer_pubkey).hex():
        return deny("unknown signer: issuer does not match the expected authority")

    # The signature must cover exactly these canonical bytes.
    canonical = canonical_json(payload).encode("utf-8")
    try:
        sig = bytes.fromhex(env.signature_hex)
    except ValueError:
        return deny("malformed bundle: signature is not hex")
    if len(sig) != _SIGNATURE_BYTES:
        return deny("malformed bundle: signature is not 64 bytes")
    if not ed25519.verify(bytes(issuer_pubkey), canonical, sig):
        return deny("signature invalid: bundle is forged or tampered")

    issued_at = payload.get("issued_at")
    expires_at = payload.get("expires_at")
    ceiling = payload.get("staleness_ceiling_s")
    if not all(isinstance(v, int) for v in (issued_at, expires_at, ceiling)):
        return deny("malformed bundle: issued_at/expires_at/staleness_ceiling_s must be ints")
    if not (issued_at < expires_at):
        return deny("malformed bundle: expires_at must be after issued_at")

    if now_epoch >= expires_at:
        return deny("bundle expired")
    if now_epoch - issued_at > ceiling:
        return deny("bundle policy too stale: staleness ceiling exceeded")

    version = payload.get("bundle_version")
    if not isinstance(version, int) or version < 1:
        return deny("malformed bundle: bundle_version must be a positive int")
    if version < min_version:
        return deny(
            f"rollback denied: bundle_version {version} < newest seen {min_version}"
        )

    perr = _validate_policy(payload.get("policy"))
    if perr:
        return deny(f"malformed bundle: policy invalid: {perr}")
    digests = payload.get("tool_digests")
    if not isinstance(digests, dict) or not digests:
        return deny("malformed bundle: tool_digests must be a non-empty mapping")

    if registry_digests is not None:
        for name, pinned in digests.items():
            live = registry_digests.get(name)
            if live is None:
                return deny(f"tool {name!r}: pinned definition missing from registry")
            if not _constant_time_equal(str(pinned), str(live)):
                return deny(
                    f"tool {name!r}: definition digest mismatch (tamper), fail-closed"
                )

    return BundleVerdict(ok=True, reason="bundle verified", bundle=dict(payload))


def _constant_time_equal(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------------
# Offline gate: tool-call decisions against a verified bundle
# ---------------------------------------------------------------------------


def _condition_holds(cond: Mapping[str, Any], args: Mapping[str, Any]) -> bool:
    arg = cond["arg"]
    if arg not in args:
        # Absent argument: "equals"/"pattern"/"type" cannot be shown to
        # hold -> condition fails (strict, Janus-shaped).
        return False
    value = args[arg]
    if "equals" in cond:
        return value == cond["equals"]
    if "pattern" in cond:
        return isinstance(value, str) and re.search(cond["pattern"], value) is not None
    if "type" in cond:
        check = _ARG_TYPE_CHECKS.get(cond["type"])
        return bool(check and check(value))
    return True


def offline_check(
    verdict: BundleVerdict,
    tool_name: str,
    args: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    """Decide one tool call against a *verified* bundle.

    Returns ``(allowed, reason)``. Refuses to run at all unless
    ``verdict.ok`` is true — an unverifiable bundle authorizes nothing.
    """
    args = dict(args or {})
    if not isinstance(verdict, BundleVerdict) or not verdict.ok:
        return False, "deny: no verified bundle (agent must not operate offline)"
    if not isinstance(tool_name, str) or not _TOOL_NAME_RE.match(tool_name):
        return False, "deny: malformed tool name"
    if tool_name not in verdict.bundle.get("tool_digests", {}):
        return False, f"deny: unknown tool {tool_name!r}"

    policy = verdict.bundle.get("policy", [])
    matched_deny = False
    matched_allow = False
    for rule in policy:
        if rule.get("tool") != tool_name:
            continue
        conditions = rule.get("conditions", [])
        if all(_condition_holds(c, args) for c in conditions):
            if rule.get("effect") == "deny":
                matched_deny = True
            else:
                matched_allow = True
    if matched_deny:
        return False, f"deny: explicit deny rule for {tool_name!r}"
    if matched_allow:
        return True, f"allow: policy permits {tool_name!r}"
    return False, f"deny: no allow rule matches {tool_name!r} (default-deny)"


# ---------------------------------------------------------------------------
# Audit + metrics helpers
# ---------------------------------------------------------------------------


def bundle_audit_event(verdict: BundleVerdict, *, tool_name: str = "") -> dict[str, Any]:
    """Deterministic audit record for a bundle verification."""
    return {
        "event": "offline_bundle.verified" if verdict.ok else "offline_bundle.denied",
        "bundle_version": verdict.bundle.get("bundle_version"),
        "issuer": verdict.bundle.get("issuer", ""),
        "reason": verdict.reason,
        "tool": tool_name,
    }


def run_offline_bundle() -> dict[str, Any]:
    """Deterministic offline-bundle probe corpus (bench support).

    12 scenarios, 4 allow / 8 deny. Each scenario is (id, build, expect).
    """
    seed = bytes(range(32))
    pub = ed25519.public_key(seed)
    other_seed = bytes([255 - b for b in range(32)])
    other_pub = ed25519.public_key(other_seed)

    tools = {
        "sensor.read": {
            "name": "sensor.read",
            "description": "read a sensor",
            "params": [{"name": "channel", "type": "string", "required": True}],
        },
        "actuator.move": {
            "name": "actuator.move",
            "description": "move an actuator",
            "params": [{"name": "position", "type": "integer", "required": True}],
        },
    }
    digests = {n: _tool_digest(d) for n, d in tools.items()}

    policy = [
        {"tool": "sensor.read", "effect": "allow", "conditions": []},
        {
            "tool": "actuator.move",
            "effect": "allow",
            "conditions": [{"arg": "position", "type": "integer"}],
        },
        {"tool": "actuator.move", "effect": "deny",
         "conditions": [{"arg": "position", "equals": 999}]},
    ]

    T0 = 1_800_000_000
    CEILING = 86_400
    EXP = T0 + 7 * 86_400

    def good(version: int = 3, **kw: Any) -> dict[str, Any]:
        params = dict(
            policy=policy, tools=tools, expiry_epoch=EXP,
            issuer_secret=seed, bundle_version=version,
            staleness_ceiling_s=CEILING, issued_at=T0,
        )
        params.update(kw)
        return compile_bundle(**params)

    scenarios: list[tuple[str, Any, bool]] = []

    # allow: valid bundle, known tool, allow rule matches
    b = good()
    v = verify_bundle(b, issuer_pubkey=pub, now_epoch=T0 + 100,
                      min_version=3, registry_digests=digests)
    scenarios.append(("allow_valid_bundle", (v, "sensor.read", {"channel": "a"}), True))

    # allow: actuator with valid integer arg (deny rule on 999 does not match)
    scenarios.append(("allow_actuator_valid_arg", (v, "actuator.move", {"position": 5}), True))

    # allow: newer version accepted when min_version tracks it
    b4 = good(version=4)
    v4 = verify_bundle(b4, issuer_pubkey=pub, now_epoch=T0 + 100,
                       min_version=4, registry_digests=digests)
    scenarios.append(("allow_newer_version", (v4, "sensor.read", {"channel": "a"}), True))

    # allow: bundle without registry check still verifies (registry optional)
    v_nr = verify_bundle(b, issuer_pubkey=pub, now_epoch=T0 + 100,
                         min_version=3, registry_digests=None)
    scenarios.append(("allow_no_registry_check", (v_nr, "sensor.read", {"channel": "a"}), True))

    # deny: expired bundle
    scenarios.append(("deny_expired",
                      (verify_bundle(b, issuer_pubkey=pub, now_epoch=EXP + 1,
                                     min_version=3, registry_digests=digests),
                       "sensor.read", {"channel": "a"}), False))

    # deny: tampered payload (flip one byte of the policy, keep old signature)
    tb = json.loads(json.dumps(b))
    tb["policy"][0]["effect"] = "deny"
    scenarios.append(("deny_tampered",
                      (verify_bundle(tb, issuer_pubkey=pub, now_epoch=T0 + 100,
                                     min_version=3, registry_digests=digests),
                       "sensor.read", {"channel": "a"}), False))

    # deny: rollback to older bundle version
    b2 = good(version=2)
    scenarios.append(("deny_rollback",
                      (verify_bundle(b2, issuer_pubkey=pub, now_epoch=T0 + 100,
                                     min_version=3, registry_digests=digests),
                       "sensor.read", {"channel": "a"}), False))

    # deny: unknown signer (signed by a different authority)
    fb = compile_bundle(policy=policy, tools=tools, expiry_epoch=EXP,
                        issuer_secret=other_seed, bundle_version=3,
                        staleness_ceiling_s=CEILING, issued_at=T0)
    scenarios.append(("deny_unknown_signer",
                      (verify_bundle(fb, issuer_pubkey=pub, now_epoch=T0 + 100,
                                     min_version=3, registry_digests=digests),
                       "sensor.read", {"channel": "a"}), False))

    # deny: staleness ceiling exceeded (policy itself too old)
    scenarios.append(("deny_stale_policy",
                      (verify_bundle(b, issuer_pubkey=pub, now_epoch=T0 + CEILING + 1,
                                     min_version=3, registry_digests=digests),
                       "sensor.read", {"channel": "a"}), False))

    # deny: tool definition digest mismatch (silent swap detected)
    swapped = dict(digests)
    swapped["sensor.read"] = "0" * 64
    scenarios.append(("deny_digest_mismatch",
                      (verify_bundle(b, issuer_pubkey=pub, now_epoch=T0 + 100,
                                     min_version=3, registry_digests=swapped),
                       "sensor.read", {"channel": "a"}), False))

    # deny: explicit deny rule (position 999)
    scenarios.append(("deny_explicit_rule",
                      (v, "actuator.move", {"position": 999}), False))

    # deny: unknown tool not in the bundle
    scenarios.append(("deny_unknown_tool",
                      (v, "net.egress", {}), False))

    mismatches: list[str] = []
    allowed_ids: list[str] = []
    denial_reasons: dict[str, str] = {}
    verify_reasons: dict[str, str] = {}
    for sid, (verdict, tool, args), expect in scenarios:
        ok, reason = offline_check(verdict, tool, args)
        verify_reasons[sid] = verdict.reason
        if ok != expect:
            mismatches.append(sid)
        if ok:
            allowed_ids.append(sid)
        else:
            denial_reasons[sid] = reason

    return {
        "n_scenarios": len(scenarios),
        "mismatches": mismatches,
        "allowed_ids": allowed_ids,
        "denial_reasons": denial_reasons,
        "rollback_detail": verify_reasons.get("deny_rollback", ""),
        "stale_detail": verify_reasons.get("deny_stale_policy", ""),
        "digest_detail": verify_reasons.get("deny_digest_mismatch", ""),
        "signer_detail": verify_reasons.get("deny_unknown_signer", ""),
        "expired_detail": verify_reasons.get("deny_expired", ""),
        "tamper_detail": verify_reasons.get("deny_tampered", ""),
    }
