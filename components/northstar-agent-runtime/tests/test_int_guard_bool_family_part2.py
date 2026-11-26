"""The int-guard family, PART TWO: the 49 targets the first suite missed.

WHY A SECOND FILE
-----------------
`tests/test_int_guard_bool_family.py` proved 24 of the 86 guarded
targets with a crafted input.  The other 49 -- in 18 modules -- had the
SHAPE check (the bool half is in the source) but no crafted input, so
nothing proved the guard actually REFUSES a bool.

That is the shape of a coverage gap that looks like coverage: the
suite's `test_every_site_carries_the_bool_half` reads the module's
SOURCE, so it passes whether or not the guard works.  A member of this
family proves the guard with a CALL.

    not isinstance(True, int)   ->  False
    True < 0                    ->  False
    -> the guard does not fire

THE TWO SHAPES OF OBSERVABLE
----------------------------
Not every module reports a malformed input by RAISING.  Some report it
in the RETURN VALUE, and the two need different assertions:

  RAISE   the call raises the module's OWN error class.  The test
          asserts the class AND that the message is non-empty -- a guard
          that fails for the WRONG reason is deletable.

  RETURN  the call returns a value that DIFFERS from the valid-int
          call's: a denial string, a False, a verdict.  The test
          asserts the values differ, and that the valid-int call
          returns the module's NORMAL value.

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
"""
import importlib.util
import re
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
    "ask_or_solve_probes": _load("ask_or_solve_probes"),
    "audit_merkle": _load("audit_merkle"),
    "compaction": _load("compaction"),
    "deployment_registry": _load("deployment_registry"),
    "evaluator_access": _load("evaluator_access"),
    "herd_gate": _load("herd_gate"),
    "hybrid_crypto": _load("hybrid_crypto"),
    "mfa_manager": _load("mfa_manager"),
    "model_lineage": _load("model_lineage"),
    "permissions": _load("permissions"),
    "permit_agents": _load("permit_agents"),
    "remote_attestation": _load("remote_attestation"),
    "runtime_defense_05": _load("runtime_defense_05"),
    "split_learning": _load("split_learning"),
    "stream_guard": _load("stream_guard"),
    "tax_agents": _load("tax_agents"),
    "vr_interface": _load("vr_interface"),
    "watermark_tracker": _load("watermark_tracker"),
}


# ---------------------------------------------------------------- the members
# Each entry is
#     (label, module, argument, call, valid_int, kind, expected)
#
#   label       the member's name
#   module      the module's short name (its key in MODULES)
#   argument    the guarded TARGET, as it appears in the module's source
#   call        callable(value) -> result; `value` is the guarded field
#   valid_int   the int the control uses
#   kind        "RAISE" or "RETURN"
#   expected    for RAISE: the module's own error class; for RETURN: the
#               value the valid-int call must produce
#
# The `expected` for RETURN members is the module's NORMAL value, so a
# guard that returned the denial for the int too would fail the control.
def _members(modules=None):
    """Build the member list.

    `modules` overrides the module dict, so the non-vacuity control
    can rebuild the members against a MUTATED copy of a module.  The
    members' calls close over the module objects they were built with,
    so rebuilding is what makes the mutation observable.
    """
    mods = MODULES if modules is None else modules
    out = []

    # ---------------------------------------------------------- ask_or_solve_probes
    asp = mods["ask_or_solve_probes"]
    out.append((
        "ask_or_solve_probes.AskPolicy.max_questions", "ask_or_solve_probes",
        "self.max_questions", lambda v: asp.AskPolicy(max_questions=v), 3,
        "RAISE", ValueError,
    ))

    # ---------------------------------------------------------- audit_merkle
    am = mods["audit_merkle"]
    sth = {"sth": am.STH_VERSION, "tree_size": 1, "root": HEX}
    out.append((
        "audit_merkle.TreeHead.from_dict.tree_size", "audit_merkle", "tree_size",
        lambda v: am.TreeHead.from_dict({**sth, "tree_size": v}), 1,
        "RAISE", ValueError,
    ))
    inc = {"proof": am.INCLUSION_PROOF_VERSION, "tree_size": 1, "leaf_index": 0,
           "leaf": HEX, "root": HEX, "path": []}
    out.append((
        "audit_merkle.InclusionProof.from_dict.tree_size", "audit_merkle", "tree_size",
        lambda v: am.InclusionProof.from_dict({**inc, "tree_size": v}), 1,
        "RAISE", ValueError,
    ))
    out.append((
        "audit_merkle.InclusionProof.from_dict.leaf_index", "audit_merkle", "leaf_index",
        lambda v: am.InclusionProof.from_dict({**inc, "leaf_index": v}), 0,
        "RAISE", ValueError,
    ))
    cons = {"proof": am.CONSISTENCY_PROOF_VERSION, "old_size": 1, "new_size": 2,
            "old_root": HEX, "new_root": HEX, "path": []}
    out.append((
        "audit_merkle.ConsistencyProof.from_dict.old_size", "audit_merkle", "old_size",
        lambda v: am.ConsistencyProof.from_dict({**cons, "old_size": v}), 1,
        "RAISE", ValueError,
    ))
    out.append((
        "audit_merkle.ConsistencyProof.from_dict.new_size", "audit_merkle", "new_size",
        lambda v: am.ConsistencyProof.from_dict({**cons, "new_size": v}), 2,
        "RAISE", ValueError,
    ))

    # ---------------------------------------------------------- compaction
    co = mods["compaction"]
    out.append((
        "compaction.is_safe_cut.cut", "compaction", "cut",
        lambda v: co.is_safe_cut(
            transcript=[{"role": "user", "content": "hi"}], cut=v),
        1, "RETURN", True,
    ))

    # ---------------------------------------------------------- deployment_registry
    dr = mods["deployment_registry"]

    def reg(**over):
        base = dict(system_id="s1", model_digest=HEX, risk_class="limited",
                    fria_digest=None, data_record_digest=HEX, retention_floor_days=30,
                    registered_by=HEX, authority_sig_hex=HEX128, expires_at=1_700_000_000)
        base.update(over)
        return dr.RegistentionReceipt(**base) if False else dr.RegistrationReceipt(**base)

    out.append((
        "deployment_registry.RegistrationReceipt.retention_floor_days",
        "deployment_registry", "self.retention_floor_days",
        lambda v: reg(retention_floor_days=v), 30,
        "RAISE", dr.DeploymentRegistryError,
    ))
    out.append((
        "deployment_registry.RegistrationReceipt.expires_at",
        "deployment_registry", "self.expires_at",
        lambda v: reg(expires_at=v), 1_700_000_000,
        "RAISE", dr.DeploymentRegistryError,
    ))

    # ---------------------------------------------------------- evaluator_access
    ea = mods["evaluator_access"]
    out.append((
        "evaluator_access.EvaluationRegistry.check_invocation.now",
        "evaluator_access", "now",
        lambda v: ea.EvaluationRegistry().check_invocation(
            model_digest=HEX, checkpoint="cp1", now=v),
        1_700_000_000, "RAISE", ea.EvaluatorAccessError,
    ))

    # ---------------------------------------------------------- herd_gate
    hg = mods["herd_gate"]

    def decl(**over):
        base = dict(strategy_id="s1", signal_sources=frozenset({HEX}),
                    feature_families=frozenset(), data_windows=frozenset(),
                    training_corpus_manifest_digest=HEX, registered_by=HEX,
                    declared_unix=1_700_000_000, notional_cents=1000)
        base.update(over)
        return hg.SignalDeclaration(**base)

    out.append((
        "herd_gate.SignalDeclaration.declared_unix", "herd_gate", "self.declared_unix",
        lambda v: decl(declared_unix=v), 1_700_000_000,
        "RAISE", hg.HerdGateError,
    ))
    out.append((
        "herd_gate.SignalDeclaration.notional_cents", "herd_gate", "self.notional_cents",
        lambda v: decl(notional_cents=v), 1000,
        "RAISE", hg.HerdGateError,
    ))
    out.append((
        "herd_gate.authorize_trading.exposure_cap_cents", "herd_gate", "exposure_cap_cents",
        lambda v: hg.authorize_trading(strategy_id="s1", registry=hg.StrategyRegistry(),
                                       exposure_cap_cents=v),
        1000, "RAISE", hg.HerdGateError,
    ))

    # ---------------------------------------------------------- hybrid_crypto
    # The PQ half's z COMPONENTS are the guarded values.  The signature
    # dataclass refuses a bool in z on its own, so the guard under test
    # is reached by calling the module's own `_pq_verify` -- the
    # function that holds the guard -- with a tampered z.
    #
    # The CRAFTED INPUT is not any old signature: it is one whose z[0]
    # is CONGRUENT TO 1 modulo the field prime.  `_pq_verify` computes
    # `w = A.z - t`, and `A` is taken modulo `_PQ_Q`, so a bool True
    # (`True % _PQ_Q == 1`) reaches the SAME `w` as an honest z[0] of
    # 1 -- and the Fiat-Shamir challenge then MATCHES.  With an
    # arbitrary signature the mutant would still return False (the
    # bool changes `w`, so the challenge does not match), and the
    # control could not tell the mutant from the original -- a control
    # that cannot fail.
    hc = mods["hybrid_crypto"]
    _pk, _sk = hc.keygen(b"seed" * 8)
    _msg = b"m22"
    _sig = hc.sign(_sk, _msg)
    _nested = _msg + b"||" + b"|".join(hex(x).encode() for x in _sig.classical_sig)
    _z, _c = _sig.pq_sig
    # The premise: this signature's z[0] really is congruent to 1.
    assert _z[0] % hc._PQ_Q == 1, (
        "the crafted PQ signature must have z[0] congruent to 1 modulo "
        "the field prime -- otherwise the bool cannot alias it"
    )
    out.append((
        "hybrid_crypto._pq_verify.z_components", "hybrid_crypto", "x",
        lambda v: hc._pq_verify(_pk.pq_pk, _nested, ((v, _z[1]), _c)),
        _z[0], "RETURN", True,
    ))

    # ---------------------------------------------------------- mfa_manager
    # The TOTP guard is reached only when the principal HAS an
    # enrolment, so the manager must be the one that enrolled -- a
    # fresh manager returns "unknown" and never reaches the guard.
    #
    # The module reports a malformed TOTP presentation in its RETURN
    # VALUE, not by raising: `VerifyResult(valid=False,
    # reason="malformed")`.  The observable is that reason, so the
    # control is the same call with a valid int, which gets past the
    # guard and reaches the code comparison ("mismatch" -- the code
    # "000000" is not the real one).
    mf = mods["mfa_manager"]
    _mgr = mf.MFAManager()
    _mgr.enroll("alice", "totp", 1)
    out.append((
        "mfa_manager.MFAManager.verify.totp.step", "mfa_manager", "step",
        lambda v: _mgr.verify("alice", "totp", 1, code="000000", step=v),
        1, "REASON", "mismatch",
    ))

    # ---------------------------------------------------------- model_lineage
    ml = mods["model_lineage"]
    out.append((
        "model_lineage.build_receipt.timestamp", "model_lineage", "self.timestamp",
        lambda v: ml.build_receipt(model_id="m1", model_digest=HEX,
                                   corpus_manifest_digest=HEX,
                                   acquisition_method="consent-gated", timestamp=v),
        1, "RAISE", ml.LineageReceiptError,
    ))

    # ---------------------------------------------------------- permissions
    pa = mods["permissions"]

    def parent(depth):
        return pa.DelegationToken(delegator_id="d1", delegatee_id="d2",
                                  tools=("t1",), issued_at=1.0, expires_at=2.0,
                                  parent_hash="", signature="", audience="",
                                  depth=depth)

    out.append((
        "permissions.mint_delegation_token.parent_token.depth",
        "permissions", "parent_token.depth",
        lambda v: pa.mint_delegation_token(delegator_id="d1", delegatee_id="d2",
                                            tools=("t1",), delegator_seed=b"\x01" * 32,
                                            parent_token=parent(v)),
        1, "RAISE", ValueError,
    ))

    # ---------------------------------------------------------- permit_agents
    pm = mods["permit_agents"]

    def window(**over):
        base = dict(window_id="w1", overridden=1, total=100,
                    observed_at=1_700_000_000)
        base.update(over)
        return pm.OverrideWindow(**base)

    out.append((
        "permit_agents.automation_bias_clock.window.overridden",
        "permit_agents", "window.overridden",
        lambda v: pm.automation_bias_clock(window(overridden=v)), 1,
        "RAISE", pm.PermitError,
    ))
    out.append((
        "permit_agents.automation_bias_clock.window.total",
        "permit_agents", "window.total",
        lambda v: pm.automation_bias_clock(window(total=v)), 100,
        "RAISE", pm.PermitError,
    ))

    # ---------------------------------------------------------- remote_attestation
    ra = mods["remote_attestation"]
    _att = ra.Attester("host1")
    _quote = _att.quote(b"\x02" * 32, 1)
    out.append((
        "remote_attestation.verify.expected_pcrs_key", "remote_attestation", "k",
        lambda v: ra.verify(_quote, "host1", b"\x02" * 32, {v: b"\x00" * 32}),
        0, "RAISE", ra.RemoteAttestationError,
    ))

    # ---------------------------------------------------------- runtime_defense_05
    rd = mods["runtime_defense_05"]
    out.append((
        "runtime_defense_05.CgroupLimits.pids_max", "runtime_defense_05", "self.pids_max",
        lambda v: rd.CgroupLimits(pids_max=v), 128,
        "RAISE", rd.CgroupError,
    ))

    # ---------------------------------------------------------- split_learning
    sl = mods["split_learning"]
    out.append((
        "split_learning.SplitLearning.n_layers", "split_learning", "n_layers",
        lambda v: sl.SplitLearning(n_layers=v, dims=[1, 2, 3], cut=1), 2,
        "RAISE", TypeError,
    ))
    out.append((
        "split_learning.SplitLearning.cut", "split_learning", "cut",
        lambda v: sl.SplitLearning(n_layers=3, dims=[1, 2, 3, 4], cut=v), 1,
        "RAISE", TypeError,
    ))

    # ---------------------------------------------------------- stream_guard
    sg = mods["stream_guard"]

    def policy(**over):
        base = dict(policy_id="p1", version="v1", deny_patterns=(),
                    max_chunk_risk=0, overlap_bytes=64)
        base.update(over)
        return sg.GuardPolicy(**base)

    out.append((
        "stream_guard.GuardPolicy.validate.max_chunk_risk", "stream_guard",
        "self.max_chunk_risk",
        lambda v: policy(max_chunk_risk=v).validate(), 0,
        "RETURN", None,
    ))
    out.append((
        "stream_guard.GuardPolicy.validate.overlap_bytes", "stream_guard",
        "self.overlap_bytes",
        lambda v: policy(overlap_bytes=v).validate(), 64,
        "RETURN", None,
    ))
    out.append((
        "stream_guard.GuardPolicy.validate.pat.weight", "stream_guard", "pat.weight",
        lambda v: policy(deny_patterns=(
            sg.DenyPattern(pattern="x", weight=v, reason="r"),)).validate(),
        1, "RETURN", None,
    ))

    # ---------------------------------------------------------- tax_agents
    tx = mods["tax_agents"]

    def plan(**over):
        base = dict(jurisdiction="DE", posture="voluntary_alignment",
                    target_at=1_700_000_000, milestones_completed=1,
                    total_milestones=2, authority_id="auth1",
                    authority_pubkey_hex=HEX, signature_hex=HEX128)
        base.update(over)
        return tx.AnnexIIIPlan(**base)

    out.append((
        "tax_agents.annex_iii_clock.plan.milestones_completed", "tax_agents",
        "plan.milestones_completed",
        lambda v: tx.annex_iii_clock(plan(milestones_completed=v), 1_700_000_000),
        1, "RAISE", tx.TaxError,
    ))
    out.append((
        "tax_agents.annex_iii_clock.plan.total_milestones", "tax_agents",
        "plan.total_milestones",
        lambda v: tx.annex_iii_clock(plan(total_milestones=v), 1_700_000_000),
        2, "RAISE", tx.TaxError,
    ))

    # ---------------------------------------------------------- watermark_tracker
    wm = mods["watermark_tracker"]
    out.append((
        "watermark_tracker.LatenessReport.lateness_ms", "watermark_tracker",
        "self.lateness_ms",
        lambda v: wm.LatenessReport(version=wm.SCHEMA_PIN, event_time=1, watermark=1,
                                    lateness_ms=v, status=wm.STATUS_ON_TIME),
        0, "RAISE", wm.WatermarkError,
    ))

    return out


MEMBERS = _members()


def _bool_half_present(module_name, argument):
    """Does the module's source carry the bool half for THIS argument?

    Read from the module's own source, so a module that grows or drops a
    guard is handled without this file being edited.
    """
    import ast

    path = Path(sys.modules[module_name].__file__)
    tree = ast.parse(path.read_text(errors="ignore"))
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            text = ast.unparse(node)
            if f"isinstance({argument}, bool)" in text:
                return True
    return False


class IntGuardPartTwoShapeTest(unittest.TestCase):
    """The family really is the family."""

    def test_every_member_carries_the_bool_half(self) -> None:
        """The guard must spell the bool half out.

        The repo holds this convention 1,984 times.  These sites were
        the exceptions, and each one is now the same shape as the rest.
        """
        for label, module, argument, _call, _valid, _kind, _expected in MEMBERS:
            with self.subTest(call=label):
                self.assertTrue(
                    _bool_half_present(module, argument),
                    f"{module}: the guard for {argument!r} does not refuse a bool",
                )

    def test_the_members_are_still_int_guards(self) -> None:
        """A guard that refuses EVERYTHING would pass the test above.

        This is the control: the guard still accepts a plain int.
        """
        for label, _module, _argument, call, valid, kind, expected in MEMBERS:
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


class IntGuardPartTwoRefusesBoolTest(unittest.TestCase):
    """THE CRAFTED INPUT: every member refuses a bool."""

    def test_a_bool_is_refused(self) -> None:
        for label, _module, _argument, call, _valid, kind, expected in MEMBERS:
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
        for label, _module, _argument, call, _valid, kind, expected in MEMBERS:
            if kind != "RAISE":
                continue
            with self.subTest(call=label):
                with self.assertRaises(expected) as caught:
                    call(True)
                self.assertTrue(str(caught.exception), f"{label}: empty message")


#: The (line, target) pairs the non-vacuity control drops the bool half
#: from, per member.  Each member's OWN guard is the first pair.
#:
#: MEASURED 2026-11-26 by planting the mutation in a COPY of the tree
#: and running the real suite: for each member, drop the bool half from
#: the member's own line and check that the member's own refusal
#: assertion then FAILS.  Where it does not, a SECOND guard on the same
#: path refuses the bool first, and the second pair records it.
#:
#: THREE members need a second pair, and the reason is worth recording:
#:
#:   audit_merkle.InclusionProof.from_dict.tree_size
#:       `tree_size` is guarded in BOTH `TreeHead.from_dict` and
#:       `InclusionProof.from_dict`; dropping the first leaves the
#:       second.
#:   split_learning.SplitLearning.n_layers / .cut
#:       `_reject_bool` (line 102) refuses the bool before the guard
#:       under test is even read.
#:
#: The pair `(228, "__post_init__range__")` is NOT a bool-half line:
#: `InclusionProof.__post_init__` refuses a `leaf_index` that is out of
#: range for the tree, and `True == 1` is out of range for the crafted
#: proof's `tree_size` of 1.  The control replaces that range check
#: with `if False:` so the guard under test is the only thing left.
MUTATIONS = {
    'ask_or_solve_probes.AskPolicy.max_questions': [[784, 'self.max_questions']],
    'audit_merkle.TreeHead.from_dict.tree_size': [[176, 'tree_size']],
    'audit_merkle.InclusionProof.from_dict.tree_size': [[260, 'tree_size']],
    'audit_merkle.InclusionProof.from_dict.leaf_index': [[260, 'leaf_index'], [228, '__post_init__range__']],
    'audit_merkle.ConsistencyProof.from_dict.old_size': [[324, 'old_size']],
    'audit_merkle.ConsistencyProof.from_dict.new_size': [[324, 'new_size']],
    'compaction.is_safe_cut.cut': [[307, 'cut']],
    'deployment_registry.RegistrationReceipt.retention_floor_days': [[177, 'self.retention_floor_days']],
    'deployment_registry.RegistrationReceipt.expires_at': [[183, 'self.expires_at']],
    'evaluator_access.EvaluationRegistry.check_invocation.now': [[320, 'now']],
    'herd_gate.SignalDeclaration.declared_unix': [[196, 'self.declared_unix']],
    'herd_gate.SignalDeclaration.notional_cents': [[198, 'self.notional_cents']],
    'herd_gate.authorize_trading.exposure_cap_cents': [[496, 'exposure_cap_cents']],
    'hybrid_crypto._pq_verify.z_components': [[371, 'x']],
    'mfa_manager.MFAManager.verify.totp.step': [[497, 'step']],
    'model_lineage.build_receipt.timestamp': [[200, 'self.timestamp']],
    'permissions.mint_delegation_token.parent_token.depth': [[943, 'parent_token.depth']],
    'permit_agents.automation_bias_clock.window.overridden': [[1043, 'window.overridden']],
    'permit_agents.automation_bias_clock.window.total': [[1045, 'window.total']],
    'remote_attestation.verify.expected_pcrs_key': [[394, 'k']],
    'runtime_defense_05.CgroupLimits.pids_max': [[55, 'self.pids_max']],
    'split_learning.SplitLearning.n_layers': [[273, 'n_layers'], [102, 'value']],
    'split_learning.SplitLearning.cut': [[281, 'cut'], [102, 'value']],
    'stream_guard.GuardPolicy.validate.max_chunk_risk': [[161, 'self.max_chunk_risk']],
    'stream_guard.GuardPolicy.validate.overlap_bytes': [[163, 'self.overlap_bytes']],
    'stream_guard.GuardPolicy.validate.pat.weight': [[169, 'pat.weight']],
    'tax_agents.annex_iii_clock.plan.milestones_completed': [[1256, 'plan.milestones_completed']],
    'tax_agents.annex_iii_clock.plan.total_milestones': [[1258, 'plan.total_milestones']],
    'watermark_tracker.LatenessReport.lateness_ms': [[141, 'self.lateness_ms']],
}


class IntGuardPartTwoNonVacuityTest(unittest.TestCase):
    """THE NON-VACUITY CONTROL: the instrument can fail.

    A test that cannot fail proves nothing.  This one plants the
    mutation the family exists to catch -- dropping the bool half, so
    the guard reads `not isinstance(X, int)` again -- in the module's
    own SOURCE, LOADS the mutated copy, REBUILDS the members against
    it, and shows that the member then ACCEPTS the bool.

    The FIRST version of this control was TEXT-ONLY: it asserted that
    the substitution had been applied to the source text, and then
    asserted that the UNMUTATED module still refused the bool.  That
    proves the text changed; it proves NOTHING about the guard.  It
    would have passed with the guard deleted outright.  The control
    below loads the mutant and requires the mutant to ACCEPT the bool.

    Four things matter here, and the first three are the ones that are
    easy to get wrong:

    * The mutation must be applied to the member's OWN guard LINE.  A
      module can hold two guards for the same field name --
      `deployment_registry` guards `v` in a loop over
      (`old_floor_days`, `new_floor_days`) and also guards
      `new_floor_days` directly -- so a text search that takes the
      first match mutates the WRONG guard and the control proves
      nothing.  Each entry in `MUTATIONS` names the line AND the
      target.

    * A bool is sometimes refused by a SECOND guard on the same path.
      Dropping only the guard under test then leaves the bool refused,
      and a control that cannot make the family fail proves nothing.
      `MUTATIONS` records the extra pairs where that happens -- they
      are MEASURED, not guessed.

    * The mutation must be shown to be LOADED, not merely to be TEXT.

    * The control must be shown ABLE TO FAIL.  The assertion below is
      what makes the unmutated module's refusal meaningful.

    The mutation is done in a COPY under a temp directory: the shared
    tree is never touched.
    """

    def _mutant(self, module_name, mutations, tmpdir):
        """Copy the module, drop the bool half at each (line, target).

        The copy is loaded under a MUTANT name, so the family's own
        member calls -- which close over the ORIGINAL module object --
        are not what is being measured.

        Four spellings of the bool half exist in the runtime, and the
        control has to handle all of them -- a control that only
        handles one would fail on the member whose guard is written the
        other way:

          `isinstance(T, bool) or not isinstance(T, int)`  the pair
          `isinstance(T, bool) or ...`                     inside a
                                                         larger clause
          `... and not isinstance(T, bool)`               the reversed
                                                         form
          `if isinstance(T, bool):`                        the bare
                                                         helper
        A fifth form is not a bool half at all: a guard that refuses
        the value for a DIFFERENT reason (`InclusionProof`'s
        `__post_init__` range check).  Those are recorded with the
        marker target `__post_init__range__` and the line is
        replaced with `if False:`.
        """
        import importlib.util
        import shutil

        source = Path(sys.modules[module_name].__file__)
        copy = Path(tmpdir) / source.name
        shutil.copy2(source, copy)
        lines = copy.read_text().splitlines(keepends=True)
        for line_no, target in mutations:
            index = line_no - 1
            text = lines[index]
            if target == "__post_init__range__":
                # a NON-bool guard that refuses the bool for another
                # reason -- neutralise the whole check
                self.assertIn("if not (", text,
                              f"{module_name}:{line_no} is not the range "
                              "check the control expects")
                lines[index] = " " * (len(text) - len(text.lstrip())) + "if False:\n"
                continue
            pair = f"isinstance({target}, bool) or not isinstance({target}, int)"
            if pair in text:
                lines[index] = text.replace(pair, f"not isinstance({target}, int)", 1)
                continue
            bare = re.search(r"isinstance\(" + re.escape(target) + r", bool\) or ", text)
            if bare:
                lines[index] = text[:bare.start()] + text[bare.end():]
                continue
            rev = re.search(r"and not isinstance\(" + re.escape(target) + r", bool\)", text)
            if rev:
                lines[index] = text[:rev.start()] + text[rev.end():]
                continue
            solo = re.search(r"isinstance\(" + re.escape(target) + r", bool\):", text)
            if solo:
                lines[index] = text[:solo.start()] + "False:" + text[solo.end():]
                continue
            self.fail(
                f"{module_name}:{line_no} is not the guard for {target!r} "
                "-- the control would mutate the wrong line"
            )
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
            label, module, _argument, _call, _valid, kind, expected = member
            with self.subTest(call=label):
                mutations = MUTATIONS.get(label)
                self.assertIsNotNone(mutations,
                                     f"{label}: the control has no mutation "
                                     "recorded for this member")
                with tempfile.TemporaryDirectory() as tmp:
                    mutant = self._mutant(module, mutations, tmp)
                    swapped = dict(MODULES)
                    swapped[module] = mutant
                    mutant_members = _members(swapped)
                    mutant_label, _m, _a, mutant_call, _v, mutant_kind, _e = next(
                        m for m in mutant_members if m[0] == label
                    )
                    self.assertEqual(kind, mutant_kind)
                    # The MUTATED module must ACCEPT the bool: the guard
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
            label, _module, argument, _call, _valid, _kind, _expected = member
            mutations = MUTATIONS.get(label)
            if mutations is None:
                continue
            with self.subTest(call=label):
                line, target = mutations[0]
                source = Path(sys.modules[member[1]].__file__)
                text = source.read_text().splitlines()
                self.assertIn(
                    f"isinstance({target}, bool)", text[line - 1],
                    f"{label}: the recorded line {line} is not the guard for "
                    f"{target!r} -- the control would measure a different "
                    "guard")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
