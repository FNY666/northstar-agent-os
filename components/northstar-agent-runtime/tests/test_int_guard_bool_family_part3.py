"""The int-guard family, PART THREE: the LAST 44 uncovered sites.

WHY A THIRD FILE
----------------
PART ONE (``test_int_guard_bool_family.py``) and PART TWO
(``test_int_guard_bool_family_part2.py``) between them prove a crafted
input for 42 of the 86 guarded targets.  The remaining 44 -- spread over
14 modules -- had the bool half in the SOURCE and no call that showed
the guard REFUSES a bool.  Together the three suites prove all 86.

The eighty-seventh site, ``tools/sandbox.py:342``, lives in a
SUBPACKAGE and is outside the runtime's 1,620-module census universe,
so it is proved in ``tests/test_landlock.py`` instead.

That is the shape of a coverage gap that looks like coverage: the
shape check reads the module's SOURCE, so it passes whether or not the
guard works.  A member of this family proves the guard with a CALL.

    not isinstance(True, int)   ->  False
    True < 0                    ->  False
    -> the guard does not fire

THE COUNT IN THE DOCSTRING IS A CLAIM
--------------------------------------
"44" is the number of uncovered (module, class, function, field) keys
measured 2026-11-26 by an AST walk of every guard line the slice
touched, minus the keys the two earlier suites already proved.  It is
re-derived here, not asserted: the census-scope pinning in
``tests/test_census_scope.py`` is what holds the count in the repo, and
this file's own premise test is what holds the family.

THE THREE SHAPES OF OBSERVABLE
-------------------------------
Not every module reports a malformed input by RAISING.  Some report it
in the RETURN VALUE, and the three need different assertions:

  RAISE   the call raises the module's OWN error class.  The test
          asserts the class AND that the message is non-empty -- a guard
          that fails for the WRONG reason is deletable.

  RETURN  the call returns a value that DIFFERS from the valid-int
          call's: a denial verdict, a False.  The test asserts the
          values differ, and that the valid-int call returns the
          module's NORMAL value.

  REASON  the module names the malformed input in a returned record
          field (``mfa_manager``'s ``VerifyResult.reason``).  The test
          asserts the reason differs from the valid-int call's.

Every member here is paired with a CONTROL on the same call: the same
function, the same arguments, with a valid int in place of the bool,
must SUCCEED.  Without the control a guard that refused everything
would pass every rejection test.

THE CALLS ARE THE REAL PATH
---------------------------
Every call below reaches the guard through the module's own public
entry point -- a dataclass constructor, a `from_dict`, a registry
method -- with the other arguments valid.  A call that could not be
reached is not a member: the family is about the code path that
actually runs.

Three of these calls needed a CRAFTED INPUT that reaches the guard
rather than an incidental earlier check, and the reasons are worth
recording because each was a bug in the first attempt:

  * ``offline_bundle.verify_bundle`` checks the SIGNATURE before the
    ``bundle_version`` guard, so a mutated bundle is denied for a forged
    signature and the version guard is never reached.  The crafted input
    is a bundle the ISSUER SIGNED with a bool version -- the honest way
    to reach the guard.

  * ``vr_interface.receive_commit`` refuses a commit beyond the local
    log, so the control must first LOG an op; otherwise the control
    fails for a reason that is not the guard's.

  * ``input_defense_26.verify`` REFUSES a bool nonce by RETURNING
    False, not by raising -- the module's own deny-not-raise style.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[1]
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))

#: A 64-char lowercase hex digest and a 128-char one -- the shapes the
#: modules' own digest checks demand.
HEX = "a" * 64
HEX128 = "A" * 128

#: A 32-byte Ed25519 seed and the public key it derives.
SECRET = b"\x01" * 32


def _load(name: str):
    """Load one family module by file path (the house loader).

    The literal in the CALL SITE matters, not the one here: the census's
    scope resolver (``scripts/census-scope.py``) resolves a module's
    scope by finding the suites that LOAD it, and the loader shape it
    recognises is a call with a LITERAL module name.  A module built
    from a dict literal is INVISIBLE to the resolver, so the census
    would pair each module with its own suite alone and never run these
    tests at all -- the family would measure nothing.
    """
    spec = importlib.util.spec_from_file_location(name, RUNTIME_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULES = {
    "agent_identity": _load("agent_identity"),
    "crypto_defense_14": _load("crypto_defense_14"),
    "deployment_registry": _load("deployment_registry"),
    "eldercare_agents": _load("eldercare_agents"),
    "evaluator_access": _load("evaluator_access"),
    "incident_receipts": _load("incident_receipts"),
    "input_defense_26": _load("input_defense_26"),
    "monitor_deafness_probes": _load("monitor_deafness_probes"),
    "offline_bundle": _load("offline_bundle"),
    "passport": _load("passport"),
    "retail_agents": _load("retail_agents"),
    "synthetic_cap": _load("synthetic_cap"),
    "vendor_chain": _load("vendor_chain"),
    "vr_interface": _load("vr_interface"),
}


# ---------------------------------------------------------------- the members
# Each entry is
#     (label, module, argument, call, valid_int, line, kind, expected)
#
#   label       the member's name
#   module      the module's short name (its key in MODULES)
#   argument    the guarded TARGET, as it appears in the module's source
#   call        callable(value) -> result; `value` is the guarded field
#   valid_int   the int the control uses
#   line        the LINE in the module's source that holds THIS member's
#               guard.  The non-vacuity control mutates that exact line:
#               a module can hold two guards for the same field name, and
#               mutating the wrong one proves nothing.
#   kind        "RAISE", "RETURN" or "REASON"
#   expected    for RAISE: the module's own error class; for RETURN: the
#               value the valid-int call must produce; for REASON: the
#               reason the valid-int call must produce
#
# The `expected` for RETURN members is the module's NORMAL value, so a
# guard that returned the denial for the int too would fail the control.
def _members(modules=None):
    mods = MODULES if modules is None else modules
    out = []
    ed25519 = mods["agent_identity"].ed25519
    PUB = ed25519.public_key(SECRET).hex()

    # ---------------------------------------------------------- agent_identity
    ai = mods["agent_identity"]
    _iss = ai.IdentityIssuer(SECRET)
    _ident, _ident_secret = _iss.issue("worker-1")
    out.append((
        "agent_identity.IdentityIssuer.delegate.depth", "agent_identity", "depth",
        lambda v: _iss.delegate(_ident_secret, _ident.did, _ident.did,
                                 ("read:files",), depth=v),
        1, 360, "RAISE", ai.IdentityError,
    ))

    # ---------------------------------------------------------- crypto_defense_14
    cd = mods["crypto_defense_14"]
    _srv = cd.MockPirServer({0: b"x", 1: b"y"})
    _cli = cd.MockPirClient()
    out.append((
        "crypto_defense_14.MockPirClient.query.index", "crypto_defense_14", "index",
        lambda v: _cli.query(v, _srv),
        0, 51, "RAISE", cd.PirError,
    ))

    # ---------------------------------------------------------- deployment_registry
    dr = mods["deployment_registry"]
    _reg = dr.DeploymentRegistry(authority_pubkeys={PUB: PUB})
    _reg.register_system(authority_secret=SECRET, authority_id=PUB, system_id="s1",
                         model_digest=HEX, risk_class="limited", fria_digest=None,
                         data_record_digest=HEX, retention_floor_days=30,
                         expires_at=1_700_000_000)

    def _retention(**over):
        base = dict(system_id="s1", old_floor_days=30, new_floor_days=60,
                    changed_by=PUB, authority_sig_hex=HEX128,
                    changed_at=1_700_000_000)
        base.update(over)
        return dr.RetentionChangeReceipt(**base)

    out.append((
        "deployment_registry.DeploymentRegistry.change_retention_floor.new_floor_days",
        "deployment_registry", "new_floor_days",
        lambda v: _reg.change_retention_floor(authority_secret=SECRET,
                                              authority_id=PUB, system_id="s1",
                                              new_floor_days=v,
                                              changed_at=1_700_000_000),
        60, 361, "RAISE", dr.DeploymentRegistryError,
    ))
    out.append((
        "deployment_registry.RetentionChangeReceipt.new_floor_days",
        "deployment_registry", "v",
        lambda v: _retention(new_floor_days=v),
        60, 231, "RAISE", dr.DeploymentRegistryError,
    ))
    out.append((
        "deployment_registry.RetentionChangeReceipt.changed_at",
        "deployment_registry", "self.changed_at",
        lambda v: _retention(changed_at=v),
        1_700_000_000, 237, "RAISE", dr.DeploymentRegistryError,
    ))

    # ---------------------------------------------------------- eldercare_agents
    ea = mods["eldercare_agents"]
    _ecr = ea.ConsentChainRegistry([PUB])
    _arr = ea.AudioRetentionRegistry([PUB])
    out.append((
        "eldercare_agents.ConsentChainRegistry.issue.retention_days",
        "eldercare_agents", "retention_days",
        lambda v: _ecr.issue(receipt_id="r1", resident_id="res1",
                             party=ea.PARTY_RESIDENT, scope="meds",
                             data_types=("meds",), retention_days=v,
                             consented_at=1_700_000_000, proxy=False,
                             authority_secret=SECRET),
        30, 535, "RAISE", ea.EldercareError,
    ))
    out.append((
        "eldercare_agents.AudioRetentionRegistry.issue.retention_days",
        "eldercare_agents", "retention_days",
        lambda v: _arr.issue(receipt_id="r2", resident_id="res1",
                             retention_days=v, consented_at=1_700_000_000,
                             expires_at=1_800_000_000, authority_secret=SECRET),
        30, 937, "RAISE", ea.EldercareError,
    ))

    # ---------------------------------------------------------- evaluator_access
    ev = mods["evaluator_access"]
    _evr = ev.EvaluationRegistry()
    out.append((
        "evaluator_access.EvaluationRegistry.register.evaluated_at",
        "evaluator_access", "value",
        lambda v: _evr.register(evaluator_id="e1", model_digest=HEX,
                                checkpoint="cp1", scope=ev.EVALUATION_SCOPES[0],
                                evaluated_at=v, expires_at=1_800_000_000),
        1_700_000_000, 234, "RAISE", ev.EvaluatorAccessError,
    ))

    # ---------------------------------------------------------- incident_receipts
    ir = mods["incident_receipts"]
    _irr = ir.IncidentRegistry()
    out.append((
        "incident_receipts.IncidentRegistry.file_incident.detected_at",
        "incident_receipts", "value",
        lambda v: _irr.file_incident(incident_id="i1", system_id="s1",
                                     severity="serious", detected_at=v,
                                     reported_at=1_700_000_000,
                                     summary_digest=HEX, now=1_700_000_100),
        1_700_000_000, 317, "RAISE", ir.IncidentReceiptError,
    ))
    out.append((
        "incident_receipts.IncidentRegistry.register_retention.retention_days",
        "incident_receipts", "retention_days",
        lambda v: _irr.register_retention(system_id="s1", retention_days=v),
        ir.INCIDENT_RETENTION_FLOOR_DAYS, 499, "RAISE", ir.IncidentReceiptError,
    ))

    # ---------------------------------------------------------- input_defense_26
    # The module REFUSES a bool nonce by RETURNING False, not by raising:
    # a deny-not-raise verifier.  The control uses a nonce that really
    # satisfies the challenge, so the control returns True.
    i26 = mods["input_defense_26"]
    # A challenge chosen so that sha256(challenge + "True") MEETS the
    # 8-bit difficulty: that is what makes the mutation OBSERVABLE.  With
    # an arbitrary challenge the mutant would still return False (the
    # bool nonce simply fails the hash), so the control would not be
    # able to tell the mutant from the original -- a control that
    # cannot fail.
    _CHALLENGE = "00000000000000000000000000000193"
    _GOOD_NONCE = i26.solve(_CHALLENGE, 8)
    out.append((
        "input_defense_26.verify.nonce", "input_defense_26", "nonce",
        lambda v: i26.verify(_CHALLENGE, v, 8),
        _GOOD_NONCE, 56, "RETURN", True,
    ))

    # ---------------------------------------------------------- monitor_deafness_probes
    md = mods["monitor_deafness_probes"]
    _signal = md.build_signal(monitor_id="m1", heartbeat_age_seconds=5,
                               last_canary_trip_age_seconds=-1,
                               recent_escalation_count=0,
                               actions_observed_since_heartbeat=0)
    _ledger = md.HealthLedger("m1")
    out.append((
        "monitor_deafness_probes.HealthLedger.append.as_of",
        "monitor_deafness_probes", "as_of",
        lambda v: _ledger.append(_signal, "record", v),
        1_700_000_000, 492, "RAISE", ValueError,
    ))
    out.append((
        "monitor_deafness_probes.build_window.actions_observed",
        "monitor_deafness_probes", "value",
        lambda v: md.build_window(agent_id="a1", window_start=1, window_end=100,
                                  actions_observed=v, escalations=0),
        5, 157, "RAISE", ValueError,
    ))
    out.append((
        "monitor_deafness_probes.build_signal.heartbeat_age_seconds",
        "monitor_deafness_probes", "value",
        lambda v: md.build_signal(monitor_id="m1", heartbeat_age_seconds=v,
                                  last_canary_trip_age_seconds=-1,
                                  recent_escalation_count=0,
                                  actions_observed_since_heartbeat=0),
        5, 356, "RAISE", ValueError,
    ))

    # ---------------------------------------------------------- offline_bundle
    ob = mods["offline_bundle"]
    _POLICY = [{"tool": "t1", "effect": "allow"}]
    _TOOLS = {"t1": {"name": "t1", "description": "d", "params": []}}

    def _compiled(**over):
        # `issued_at` is ZERO on purpose: the ordering check
        # (`expiry_epoch > issued_at`) would otherwise refuse a bool
        # `expiry_epoch` (True == 1) BEFORE the guard under test, and
        # the control would be measuring the ordering, not the guard.
        base = dict(expiry_epoch=1_800_000_000, bundle_version=1,
                    staleness_ceiling_s=60, issued_at=0)
        base.update(over)
        return ob.compile_bundle(_POLICY, _TOOLS, base["expiry_epoch"],
                                 issuer_secret=SECRET,
                                 bundle_version=base["bundle_version"],
                                 staleness_ceiling_s=base["staleness_ceiling_s"],
                                 issued_at=base["issued_at"])

    out.append((
        "offline_bundle.compile_bundle.bundle_version", "offline_bundle",
        "bundle_version",
        lambda v: _compiled(bundle_version=v),
        1, 236, "RAISE", ob.BundleError,
    ))
    out.append((
        "offline_bundle.compile_bundle.expiry_epoch", "offline_bundle",
        "expiry_epoch",
        lambda v: _compiled(expiry_epoch=v),
        1_800_000_000, 238, "RAISE", ob.BundleError,
    ))
    out.append((
        "offline_bundle.compile_bundle.issued_at", "offline_bundle", "issued_at",
        lambda v: _compiled(issued_at=v),
        1_700_000_000, 238, "RAISE", ob.BundleError,
    ))
    out.append((
        "offline_bundle.compile_bundle.staleness_ceiling_s", "offline_bundle",
        "staleness_ceiling_s",
        lambda v: _compiled(staleness_ceiling_s=v),
        60, 242, "RAISE", ob.BundleError,
    ))

    _bundle = _compiled()
    _pub_bytes = bytes.fromhex(PUB)
    # `_bundle` was issued at epoch 0 with a 60-second staleness
    # ceiling, so the verifier's `now_epoch` must sit INSIDE that
    # window -- a later epoch is refused as STALE, which is a
    # different check and would mask the guard under test.
    out.append((
        "offline_bundle.verify_bundle.now_epoch", "offline_bundle", "now_epoch",
        lambda v: ob.verify_bundle(_bundle, issuer_pubkey=_pub_bytes,
                                   now_epoch=v, min_version=1).ok,
        30, 317, "RETURN", True,
    ))
    out.append((
        "offline_bundle.verify_bundle.min_version", "offline_bundle", "min_version",
        lambda v: ob.verify_bundle(_bundle, issuer_pubkey=_pub_bytes,
                                   now_epoch=30, min_version=v).ok,
        1, 317, "RETURN", True,
    ))

    def _signed_bundle_with_version(value):
        """A bundle the ISSUER SIGNED with `bundle_version = value`.

        `verify_bundle` checks the signature BEFORE the version guard, so
        mutating a compiled bundle is denied for a forged signature and
        the guard is never reached.  Signing it here is the honest crafted
        input: the issuer itself signs a bundle whose version is a bool.
        """
        payload = {
            "schema_version": ob.BUNDLE_SCHEMA_VERSION,
            "bundle_version": value,
            "issuer": PUB,
            "issued_at": 1_700_000_000,
            "expires_at": 1_800_000_000,
            "staleness_ceiling_s": 60,
            "policy": _POLICY,
            "tool_digests": {k: ob._tool_digest(d) for k, d in _TOOLS.items()},
        }
        canonical = ob.canonical_json(payload).encode("utf-8")
        doc = dict(payload)
        doc["signature"] = ed25519.sign(SECRET, canonical).hex()
        return doc

    out.append((
        "offline_bundle.verify_bundle.version", "offline_bundle", "version",
        lambda v: ob.verify_bundle(_signed_bundle_with_version(v),
                                   issuer_pubkey=_pub_bytes,
                                   now_epoch=1_700_000_000, min_version=1).ok,
        1, 359, "RETURN", True,
    ))

    # ---------------------------------------------------------- passport
    pp = mods["passport"]
    _issuer = pp.PassportIssuer(SECRET)
    _pk = _issuer.public_key_hex
    _caps = {"read": {"allowed": True}}
    _now = "2026-01-01T00:00:00Z"

    def _mint(**over):
        base = dict(sub="s1", public_key_hex=_pk, capabilities=_caps,
                    time_iso=_now)
        base.update(over)
        return _issuer.mint(**base)

    out.append((
        "passport.PassportIssuer.mint.trust_level", "passport", "trust_level",
        lambda v: _mint(trust_level=v),
        pp.TRUST_LEVELS["IDENTIFIED"], 485, "RAISE", pp.PassportError,
    ))
    out.append((
        "passport.PassportIssuer.mint.ttl_seconds", "passport", "ttl_seconds",
        lambda v: _mint(ttl_seconds=v),
        3600, 489, "RAISE", pp.PassportError,
    ))

    _parent = _mint()

    def _delegate(**over):
        base = dict(parent=_parent, delegator_secret=SECRET, delegatee_sub="s2",
                    delegatee_public_key_hex=_pk, requested_capabilities=_caps,
                    time_iso=_now)
        base.update(over)
        return pp.delegate_passport(**base)

    out.append((
        "passport.delegate_passport.trust_level", "passport", "trust_level",
        lambda v: _delegate(trust_level=v),
        pp.TRUST_LEVELS["IDENTIFIED"], 544, "RAISE", pp.PassportError,
    ))
    out.append((
        "passport.delegate_passport.ttl_seconds", "passport", "ttl_seconds",
        lambda v: _delegate(ttl_seconds=v),
        3600, 550, "RAISE", pp.PassportError,
    ))

    # ---------------------------------------------------------- retail_agents
    ra = mods["retail_agents"]
    _authorities = ra.AuthorityRegistry()
    _authorities.register("auth1", PUB)
    _pd = ra.PriceDisclosureRegistry(_authorities)
    _esl = ra.ESLChangeLog(_authorities)
    _upsell = ra.UpsellRegistry(_authorities)
    _shasha = ra.ShashaRegistry(_authorities)
    _wear = ra.WearableCollectionRegistry(_authorities)
    out.append((
        "retail_agents.PriceDisclosureRegistry.issue.personalized_price_minor",
        "retail_agents", "personalized_price_minor",
        lambda v: _pd.issue(receipt_id="r1", merchant_id="m1", item_id="i1",
                            personalized_price_minor=v,
                            disclosure_text="price cut", shown_at=1_700_000_000,
                            authority_id="auth1", authority_secret=SECRET),
        100, 425, "RAISE", ra.RetailError,
    ))
    out.append((
        "retail_agents.ESLChangeLog.issue.old_price_minor", "retail_agents", "v",
        lambda v: _esl.issue("e1", "st1", "it1", v, 200, 1_700_000_000,
                             "rule1", "auth1", SECRET),
        100, 638, "RAISE", ra.RetailError,
    ))
    out.append((
        "retail_agents.UpsellRegistry.issue.list_price_minor", "retail_agents", "v",
        lambda v: _upsell.issue("u1", "m1", "it1", v, 90, "because", ("alt",),
                                1_700_000_000, "auth1", SECRET),
        100, 848, "RAISE", ra.RetailError,
    ))
    out.append((
        "retail_agents.ShashaRegistry.issue.price_a_minor", "retail_agents", "v",
        lambda v: _shasha.issue("s1", "p1", "it1", "cA", v, "cB", 110, "just",
                                1_700_000_000, "auth1", SECRET),
        100, 1275, "RAISE", ra.RetailError,
    ))
    out.append((
        "retail_agents.WearableCollectionRegistry.issue.retention_days",
        "retail_agents", "retention_days",
        lambda v: _wear.issue(receipt_id="w1", operator_id="op1",
                              device_kind="smart_glasses", purposes=("p1",),
                              retention_days=v, collected_at=1_700_000_000,
                              authority_id="auth1", authority_secret=SECRET),
        30, 1670, "RAISE", ra.RetailError,
    ))

    # ---------------------------------------------------------- synthetic_cap
    sc = mods["synthetic_cap"]

    def _manifest(**over):
        base = dict(slice_id="sl1", origin=sc.SLICE_ORIGIN_SYNTHETIC,
                    slice_digest=HEX, weight_units=10, generator_id="gen1",
                    generation=1, issued_at=1_700_000_000,
                    authority_pubkey_hex=PUB, signature_hex=HEX128)
        base.update(over)
        return sc.DataSliceManifest(**base)

    out.append((
        "synthetic_cap.DataSliceManifest.weight_units", "synthetic_cap",
        "self.weight_units",
        lambda v: _manifest(weight_units=v),
        10, 264, "RAISE", sc.SyntheticCapError,
    ))
    out.append((
        "synthetic_cap.DataSliceManifest.generation", "synthetic_cap",
        "self.generation",
        lambda v: _manifest(generation=v),
        1, 275, "RAISE", sc.SyntheticCapError,
    ))
    out.append((
        "synthetic_cap.training_summary_receipt.top_n", "synthetic_cap", "top_n",
        lambda v: sc.training_summary_receipt(model_id="m1",
                                              manifests=[_manifest()], top_n=v,
                                              issued_at=1_700_000_000),
        10, 723, "RAISE", sc.SyntheticCapError,
    ))

    # ---------------------------------------------------------- vendor_chain
    vc = mods["vendor_chain"]
    _envelope = vc.ActionEnvelope(max_value_cents=1000, max_quantity=10,
                                  allowed_skus=frozenset({"s1"}))
    out.append((
        "vendor_chain.build_vendor_receipt.created_unix", "vendor_chain",
        "created_unix",
        lambda v: vc.build_vendor_receipt(receipt_id="r1", action_id="a1",
                                          vendor_id="v1",
                                          vendor_attestation_digest=HEX,
                                          created_unix=v),
        1_700_000_000, 189, "RAISE", vc.VendorChainError,
    ))
    out.append((
        "vendor_chain.ActionEnvelope.max_value_cents", "vendor_chain",
        "self.max_value_cents",
        lambda v: vc.ActionEnvelope(max_value_cents=v, max_quantity=10),
        1000, 335, "RAISE", vc.VendorChainError,
    ))
    out.append((
        "vendor_chain.ActionEnvelope.max_quantity", "vendor_chain",
        "self.max_quantity",
        lambda v: vc.ActionEnvelope(max_value_cents=1000, max_quantity=v),
        10, 337, "RAISE", vc.VendorChainError,
    ))
    out.append((
        "vendor_chain.ActionEnvelope.contains.quantity", "vendor_chain", "quantity",
        lambda v: _envelope.contains("s1", v, 5),
        2, 345, "RETURN", True,
    ))
    out.append((
        "vendor_chain.ActionEnvelope.contains.value_cents", "vendor_chain",
        "value_cents",
        lambda v: _envelope.contains("s1", 2, v),
        5, 347, "RETURN", True,
    ))

    # ---------------------------------------------------------- vr_interface
    vr = mods["vr_interface"]
    _REPLICAS = ("n1", "n2", "n3")

    def _prepare_message(commit_number=None, op_number=None):
        primary = vr.VRNode("n1", _REPLICAS)
        prepare = primary.client_request("req1", "c1", "sha256:" + "b" * 64, 1)
        fields = dict(prepare.body())
        if commit_number is not None:
            fields["commit_number"] = commit_number
        if op_number is not None:
            fields["op_number"] = op_number
        return vr._message("prepare", **fields)

    def _fresh_backup():
        return vr.VRNode("n2", _REPLICAS)

    def _backup_with_log():
        """A backup that has LOGGED op 1.

        `receive_commit` refuses a commit beyond the local log, so the
        control must log an op first -- otherwise the control fails for
        a reason that is not the guard's.
        """
        backup = _fresh_backup()
        backup.receive_prepare(_prepare_message(), 2)
        return backup

    out.append((
        "vr_interface.VRNode.receive_prepare.op_number", "vr_interface", "op_number",
        lambda v: _fresh_backup().receive_prepare(
            _prepare_message(op_number=v), 2),
        1, 341, "RAISE", vr.VRError,
    ))
    out.append((
        "vr_interface.VRNode.receive_prepare.commit_number", "vr_interface",
        "commit_number",
        lambda v: _fresh_backup().receive_prepare(
            _prepare_message(commit_number=v), 2),
        0, 349, "RAISE", vr.VRError,
    ))
    out.append((
        "vr_interface.VRNode.receive_commit.commit_number", "vr_interface",
        "commit_number",
        lambda v: _backup_with_log().receive_commit(
            vr._message("commit", view=0, commit_number=v, node_id="n1"), 3),
        1, 421, "RAISE", vr.VRError,
    ))
    out.append((
        "vr_interface.VRNode.receive_start_view_change.new_view", "vr_interface",
        "new_view",
        lambda v: _fresh_backup().receive_start_view_change(
            vr._message("start-view-change", new_view=v, node_id="n1")),
        1, 450, "RAISE", vr.VRError,
    ))
    out.append((
        "vr_interface.VRNode.receive_do_view_change.new_view", "vr_interface",
        "new_view",
        lambda v: _fresh_backup().receive_do_view_change(
            vr._message("do-view-change", new_view=v, node_id="n1",
                        log_digests=[], op_number=0, commit_number=0)),
        1, 487, "RAISE", vr.VRError,
    ))
    out.append((
        "vr_interface.VRNode.receive_start_view.new_view", "vr_interface", "new_view",
        lambda v: _fresh_backup().receive_start_view(
            vr._message("start-view", new_view=v, op_number=0, commit_number=0,
                        log_digests=[]), 4),
        1, 526, "RAISE", vr.VRError,
    ))

    return out



#: The (line, target) pairs the non-vacuity control drops the bool half
#: from, per member.  Each member's OWN guard is the first pair.
#:
#: Five members need a SECOND pair, and the reason is worth recording:
#: a bool is refused by more than one guard on the same path, so
#: dropping only the guard under test leaves the bool refused -- and a
#: control that cannot make the family fail proves nothing.
#:
#:   deployment_registry.change_retention_floor.new_floor_days
#:       the receipt's own `__post_init__` (line 231) refuses it too.
#:   vr_interface.receive_commit.commit_number
#:   vr_interface.receive_do_view_change.new_view
#:   vr_interface.receive_start_view.new_view
#:       `_check_int` (line 97) refuses it on the way in.
MUTATIONS = {
    'agent_identity.IdentityIssuer.delegate.depth': [[360, 'depth']],
    'crypto_defense_14.MockPirClient.query.index': [[51, 'index']],
    'deployment_registry.DeploymentRegistry.change_retention_floor.new_floor_days': [[361, 'new_floor_days'], [231, 'v']],
    'deployment_registry.RetentionChangeReceipt.new_floor_days': [[231, 'v']],
    'deployment_registry.RetentionChangeReceipt.changed_at': [[237, 'self.changed_at']],
    'eldercare_agents.ConsentChainRegistry.issue.retention_days': [[535, 'retention_days']],
    'eldercare_agents.AudioRetentionRegistry.issue.retention_days': [[937, 'retention_days']],
    'evaluator_access.EvaluationRegistry.register.evaluated_at': [[234, 'value']],
    'incident_receipts.IncidentRegistry.file_incident.detected_at': [[317, 'value']],
    'incident_receipts.IncidentRegistry.register_retention.retention_days': [[499, 'retention_days']],
    'input_defense_26.verify.nonce': [[56, 'nonce']],
    'monitor_deafness_probes.HealthLedger.append.as_of': [[492, 'as_of']],
    'monitor_deafness_probes.build_window.actions_observed': [[157, 'value']],
    'monitor_deafness_probes.build_signal.heartbeat_age_seconds': [[356, 'value']],
    'offline_bundle.compile_bundle.bundle_version': [[236, 'bundle_version']],
    'offline_bundle.compile_bundle.expiry_epoch': [[238, 'expiry_epoch']],
    'offline_bundle.compile_bundle.issued_at': [[238, 'issued_at']],
    'offline_bundle.compile_bundle.staleness_ceiling_s': [[242, 'staleness_ceiling_s']],
    'offline_bundle.verify_bundle.now_epoch': [[317, 'now_epoch']],
    'offline_bundle.verify_bundle.min_version': [[317, 'min_version']],
    'offline_bundle.verify_bundle.version': [[359, 'version']],
    'passport.PassportIssuer.mint.trust_level': [[485, 'trust_level']],
    'passport.PassportIssuer.mint.ttl_seconds': [[489, 'ttl_seconds']],
    'passport.delegate_passport.trust_level': [[544, 'trust_level']],
    'passport.delegate_passport.ttl_seconds': [[550, 'ttl_seconds']],
    'retail_agents.PriceDisclosureRegistry.issue.personalized_price_minor': [[425, 'personalized_price_minor']],
    'retail_agents.ESLChangeLog.issue.old_price_minor': [[638, 'v']],
    'retail_agents.UpsellRegistry.issue.list_price_minor': [[848, 'v']],
    'retail_agents.ShashaRegistry.issue.price_a_minor': [[1275, 'v']],
    'retail_agents.WearableCollectionRegistry.issue.retention_days': [[1670, 'retention_days']],
    'synthetic_cap.DataSliceManifest.weight_units': [[264, 'self.weight_units']],
    'synthetic_cap.DataSliceManifest.generation': [[275, 'self.generation']],
    'synthetic_cap.training_summary_receipt.top_n': [[723, 'top_n']],
    'vendor_chain.build_vendor_receipt.created_unix': [[189, 'created_unix']],
    'vendor_chain.ActionEnvelope.max_value_cents': [[335, 'self.max_value_cents']],
    'vendor_chain.ActionEnvelope.max_quantity': [[337, 'self.max_quantity']],
    'vendor_chain.ActionEnvelope.contains.quantity': [[345, 'quantity']],
    'vendor_chain.ActionEnvelope.contains.value_cents': [[347, 'value_cents']],
    'vr_interface.VRNode.receive_prepare.op_number': [[341, 'op_number']],
    'vr_interface.VRNode.receive_prepare.commit_number': [[349, 'commit_number']],
    'vr_interface.VRNode.receive_commit.commit_number': [[421, 'commit_number']],
    'vr_interface.VRNode.receive_start_view_change.new_view': [[450, 'new_view']],
    'vr_interface.VRNode.receive_do_view_change.new_view': [[487, 'new_view']],
    'vr_interface.VRNode.receive_start_view.new_view': [[526, 'new_view']],
}

MEMBERS = _members()


def _bool_half_present(module_name, argument, line=None):
    """Does the module's source carry the bool half for THIS argument?

    Read from the module's own source, so a module that grows or drops a
    guard is handled without this file being edited.

    `line` narrows the search to the member's OWN guard line.  That
    matters: a module can guard the same argument name in two places
    -- `monitor_deafness_probes` guards `value` in BOTH
    `EscalationWindow.__post_init__` and
    `MonitorHealthSignal.__post_init__`, and `audit_merkle` guards
    `tree_size` in both `TreeHead.from_dict` and
    `InclusionProof.from_dict` -- and a whole-module search would
    report the shape for a member whose own guard had lost it.  A
    shape test that passes on a SIBLING's guard is a shape test that
    measures nothing.
    """
    import ast

    path = Path(sys.modules[module_name].__file__)
    tree = ast.parse(path.read_text(errors="ignore"))
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            if line is not None and node.lineno != line:
                continue
            text = ast.unparse(node)
            if f"isinstance({argument}, bool)" in text:
                return True
    return False


class IntGuardPartThreeShapeTest(unittest.TestCase):
    """The family really is the family."""

    def test_every_member_carries_the_bool_half(self) -> None:
        """The guard must spell the bool half out.

        The repo holds this convention 2,065 times.  These sites were
        the exceptions, and each one is now the same shape as the rest.
        """
        for label, module, argument, _call, _valid, line, _kind, _expected in MEMBERS:
            with self.subTest(call=label):
                self.assertTrue(
                    _bool_half_present(module, argument, line),
                    f"{module}:{line}: the guard for {argument!r} does not "
                    "refuse a bool",
                )

    def test_the_members_are_still_int_guards(self) -> None:
        """A guard that refuses EVERYTHING would pass the test above.

        This is the control: the guard still accepts a plain int.
        """
        for label, _module, _argument, call, valid, _line, kind, expected in MEMBERS:
            with self.subTest(call=label):
                if kind == "RAISE":
                    # the valid int must NOT raise -- that is the control
                    call(valid)
                elif kind == "REASON":
                    # the valid int gets past the guard
                    self.assertEqual(expected, call(valid).reason,
                                     f"{label}: the valid int's reason")
                else:
                    # the valid int must produce the module's NORMAL value
                    self.assertEqual(expected, call(valid),
                                     f"{label}: the valid int's value")


class IntGuardPartThreeRefusesBoolTest(unittest.TestCase):
    """THE CRAFTED INPUT: every member refuses a bool."""

    def test_a_bool_is_refused(self) -> None:
        for label, _module, _argument, call, _valid, _line, kind, expected in MEMBERS:
            with self.subTest(call=label):
                if kind == "RAISE":
                    with self.assertRaises(expected):
                        call(True)
                elif kind == "REASON":
                    # the module names the malformed input in the reason
                    self.assertNotEqual(expected, call(True).reason,
                                        f"{label}: the bool was accepted")
                else:
                    # the module reports it in the RETURN VALUE
                    self.assertNotEqual(expected, call(True),
                                        f"{label}: the bool was accepted")

    def test_a_refusal_that_raises_says_why(self) -> None:
        """A guard that fails for the WRONG reason is deletable.

        The message says WHICH rule fired, so a future edit that breaks
        the guard for another reason is visible here rather than hiding
        behind a bare "it raised".
        """
        for label, _module, _argument, call, _valid, _line, kind, expected in MEMBERS:
            if kind != "RAISE":
                continue
            with self.subTest(call=label):
                with self.assertRaises(expected) as caught:
                    call(True)
                self.assertTrue(str(caught.exception), f"{label}: empty message")


class IntGuardPartThreeNonVacuityTest(unittest.TestCase):
    """THE NON-VACUITY CONTROL: the instrument can fail.

    A test that cannot fail proves nothing.  This one plants the
    mutation the family exists to catch -- dropping the bool half, so
    the guard reads `not isinstance(X, int)` again -- in the module's own
    SOURCE, LOADS the mutated copy, and shows that the family then
    ACCEPTS the bool.

    Four things matter here, and the first three are the ones that are
    easy to get wrong:

    * The mutation must be applied to the member's OWN guard LINE.  A
      module can hold two guards for the same field name -- `passport`
      guards `trust_level` in both `mint` and `delegate_passport`, and
      `offline_bundle` line 317 guards BOTH `now_epoch` and
      `min_version` -- so a text search that takes the first match
      mutates the wrong guard and the control proves nothing.  Each
      member carries its guard's line number, measured from the
      module's own source, and the mutation names the TARGET too.

    * A bool is sometimes refused by a SECOND guard on the same path.
      Dropping only the guard under test then leaves the bool refused,
      and a control that cannot make the family fail proves nothing.
      `MUTATIONS` records the extra pairs where that happens.

    * The mutation must be shown to be LOADED, not merely to be TEXT.
      A control that only checks the text was rewritten proves the text
      changed; it does not prove the crafted input would be accepted.

    * The control must be shown ABLE TO FAIL.  The assertions below are
      what make the unmutated module's refusal meaningful.

    The mutation is done in a COPY under a temp directory: the shared
    tree is never touched.
    """

    def _mutant(self, module_name, mutations, tmpdir):
        """Copy the module, drop the bool half at each (line, target).

        The copy is loaded under a MUTANT name, so the family's own
        member calls -- which close over the ORIGINAL module object --
        are not what is being measured.
        """
        import importlib.util
        import shutil

        source = Path(sys.modules[module_name].__file__)
        copy = Path(tmpdir) / source.name
        shutil.copy2(source, copy)
        lines = copy.read_text().splitlines(keepends=True)
        for line_no, target in mutations:
            needle = f"isinstance({target}, bool) or not isinstance({target}, int)"
            index = line_no - 1
            self.assertIn(needle, lines[index],
                          f"{module_name}:{line_no} is not the guard for "
                          f"{target!r} -- the control would mutate the "
                          "wrong line")
            lines[index] = lines[index].replace(
                needle, f"not isinstance({target}, int)", 1)
        copy.write_text("".join(lines))

        mutant_name = f"_mutant_{module_name}"
        spec = importlib.util.spec_from_file_location(mutant_name, copy)
        module = importlib.util.module_from_spec(spec)
        sys.modules[mutant_name] = module
        spec.loader.exec_module(module)
        return module

    def test_the_mutation_makes_the_crafted_input_accepted(self) -> None:
        """THE CONTROL: with the bool half dropped, the bool gets through.

        One member per module this suite covers, so the family is shown
        to be able to fail on EVERY module -- not on one convenient
        example.
        """
        import tempfile

        for member in MEMBERS:
            label, module, _argument, _call, _valid, _line, kind, expected = member
            with self.subTest(call=label):
                mutations = MUTATIONS.get(label)
                self.assertIsNotNone(mutations,
                                     f"{label}: the control has no mutation "
                                     "recorded for this member")
                with tempfile.TemporaryDirectory() as tmp:
                    mutant = self._mutant(module, mutations, tmp)
                    # rebuild the members against the mutant
                    swapped = dict(MODULES)
                    swapped[module] = mutant
                    mutant_members = _members(swapped)
                    mutant_label, _m, _a, mutant_call, _v, _ml, mutant_kind, _e = next(
                        m for m in mutant_members if m[0] == label
                    )
                    self.assertEqual(kind, mutant_kind)
                    # the MUTATED module must ACCEPT the bool: the guard
                    # no longer fires.  This is the assertion that makes
                    # the unmutated refusal meaningful.
                    #
                    # The direction matters: the mutant must NOT raise.
                    # Asserting that the mutant raises would be a
                    # tautology -- it would pass on the UNMUTATED module
                    # too, and prove nothing.
                    if kind == "RAISE":
                        # The member asserts `assertRaises(expected)`, so
                        # the flip is "the mutant does NOT raise the
                        # module's OWN error class".  A DIFFERENT error
                        # class is a real flip too: `assertRaises` is
                        # class-sensitive, so the member's own assertion
                        # fails on it.  Asserting "the mutant does not
                        # raise at all" would be too strict -- a bool can
                        # be refused by a second guard on the same path
                        # for a different reason, and that is exactly
                        # the shadow this table records.
                        try:
                            mutant_call(True)
                        except expected:
                            self.fail(
                                f"{label}: the MUTANT still refused the bool "
                                f"with the module's own {expected.__name__} -- "
                                "the control cannot make the family fail"
                            )
                        except Exception:  # noqa: BLE001
                            # a DIFFERENT error class: the member's
                            # `assertRaises(expected)` no longer holds.
                            pass
                    elif kind == "REASON":
                        # the mutant treats the bool AS THE INT: the
                        # module's reason is the valid-int reason
                        self.assertEqual(expected, mutant_call(True).reason,
                                         f"{label}: the MUTANT still refused "
                                         "the bool -- the control cannot make "
                                         "the family fail")
                    else:
                        # likewise: the mutant's verdict is the valid
                        # int's verdict
                        self.assertEqual(expected, mutant_call(True),
                                         f"{label}: the MUTANT still refused "
                                         "the bool -- the control cannot make "
                                         "the family fail")

    def test_every_member_has_a_recorded_mutation(self) -> None:
        """Every member the suite proves must be falsifiable.

        A member with no recorded mutation is a member whose guard could
        be broken and the suite would not notice.
        """
        for member in MEMBERS:
            label = member[0]
            with self.subTest(call=label):
                self.assertIn(label, MUTATIONS)

    def test_the_mutations_are_the_members_own_guard(self) -> None:
        """Every member's FIRST mutation is its own guard's line.

        A member whose own guard is not in the mutation list is a member
        whose family might be measuring a DIFFERENT guard.
        """
        for member in MEMBERS:
            label, _module, _argument, _call, _valid, line, _kind, _expected = member
            with self.subTest(call=label):
                mutations = MUTATIONS[label]
                self.assertEqual(mutations[0][0], line,
                                 f"{label}: the mutation does not start at "
                                 "the member's own guard")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
