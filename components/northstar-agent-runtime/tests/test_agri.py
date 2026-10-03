"""Tests for the agriculture extension (one-hundred-sixteenth batch)."""

import hashlib
import unittest

import agri


NOW = 1_700_000_000

AUTH_SEC = hashlib.sha256(b"test/agri-authority").digest()
FARMER_SEC = hashlib.sha256(b"test/agri-farmer").digest()

AGRO = hashlib.sha256(b"test/agro").hexdigest()
MODEL_D = hashlib.sha256(b"test/model").hexdigest()
TERMS_D = hashlib.sha256(b"test/terms").hexdigest()
OTHER_AGRO = hashlib.sha256(b"test/agro-other").hexdigest()

FULL_ADVICE = {
    "why": "Yellowing on lower leaves matches nitrogen deficiency.",
    "evidence": "2024-2025 field trials, 3 counties, n=212.",
    "self_check": "Check whether the lower leaves yellow first.",
    "contact": "Extension officer: +254 700 000 000.",
    "language": "swahili",
}


def make_binding(**kw):
    args = {
        "binding_id": "agb-1",
        "capability_id": "agri/advice",
        "model_version_digest": MODEL_D,
        "crop_system": "smallholder_mixed",
        "farm_scale_class": "smallholder",
        "agroecology_digest": AGRO,
        "authority_secret": AUTH_SEC,
        "authorized_by": "agri-board",
        "authorized_at": NOW - 100,
        "expires_at": NOW + 100,
    }
    args.update(kw)
    return agri.issue_agri_binding(**args)


def make_envelope(**kw):
    args = {
        "envelope_id": "fe-1",
        "equipment_id": "sprayer/1",
        "limits": {
            "max_soil_moisture_pct": 60.0,
            "max_slope_pct": 12.0,
            "max_obstacle_density": 0.3,
            "min_visibility_m": 50.0,
        },
        "authority_secret": AUTH_SEC,
        "armed_by": "agri-board",
        "armed_at": NOW - 100,
        "expires_at": NOW + 100,
    }
    args.update(kw)
    return agri.arm_field_envelope(**args)


def make_conditions(envelope, **kw):
    args = {
        "declaration_id": "cond-1",
        "envelope": envelope,
        "soil_state": "moist",
        "obstacle_state": "sparse",
        "equipment_wear_class": "normal",
        "soil_moisture_pct": 35.0,
        "slope_pct": 5.0,
        "obstacle_density": 0.1,
        "visibility_m": 200.0,
        "declared_at": NOW - 60,
    }
    args.update(kw)
    return agri.declare_conditions(**args)


def make_receipt(**kw):
    args = {
        "receipt_id": "fdr-1",
        "farmer_id": "farmer-a",
        "farmer_secret": FARMER_SEC,
        "data_scope": "yield",
        "purpose": "yield prediction",
        "revenue_share_terms_digest": TERMS_D,
        "granted_at": NOW - 100,
        "expires_at": NOW + 100,
    }
    args.update(kw)
    return agri.farmer_data_receipt(**args)


# -- scene binding -------------------------------------------------------




class TestAgriExtension(unittest.TestCase):
    def test_bound_scene_allows(self):
        v = agri.check_agri_scene(
            make_binding(),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=AGRO,
            now=NOW,
        )
        assert v.allowed and v.reason == "agri-scene-authorized"


    def test_scale_mismatch_denies(self):
        v = agri.check_agri_scene(
            make_binding(crop_system="industrial_monoculture", farm_scale_class="industrial"),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=AGRO,
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_SCENE_MISMATCH


    def test_agroecology_digest_mismatch_denies(self):
        v = agri.check_agri_scene(
            make_binding(),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=OTHER_AGRO,
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_SCENE_MISMATCH


    def test_crop_system_mismatch_denies(self):
        v = agri.check_agri_scene(
            make_binding(crop_system="orchard_permanent"),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=AGRO,
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_SCENE_MISMATCH


    def test_expired_binding_denies(self):
        v = agri.check_agri_scene(
            make_binding(expires_at=NOW - 1),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=AGRO,
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_BINDING_EXPIRED


    def test_unknown_vocab_raises_at_issuance(self):
        with self.assertRaises(agri.AgriBoundError):
            make_binding(crop_system="space_greenhouse")


    def test_scene_audit_event_shape(self):
        v = agri.check_agri_scene(
            make_binding(),
            crop_system="smallholder_mixed",
            farm_scale_class="smallholder",
            agroecology_digest=AGRO,
            now=NOW,
        )
        ev = agri.agri_scene_audit_event(v, action="advise")
        assert ev["event"] == agri.AGRI_SCENE_ALLOWED_EVENT
        assert ev["reason"] == "agri-scene-authorized"


    # -- field envelope + conditions -----------------------------------------


    def test_actuation_inside_envelope_allows(self):
        env = make_envelope()
        v = agri.check_actuation(
            envelope=env, declaration=make_conditions(env), now=NOW
        )
        assert v.allowed and v.reason == "actuation-authorized"


    def test_no_conditions_declaration_denies(self):
        env = make_envelope()
        v = agri.check_actuation(envelope=env, declaration=None, now=NOW)
        assert not v.allowed and v.reason == agri.DENY_NO_CONDITIONS_DECLARED


    def test_moisture_above_cap_denies(self):
        env = make_envelope()
        v = agri.check_actuation(
            envelope=env,
            declaration=make_conditions(env, soil_moisture_pct=85.0, soil_state="wet"),
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_CONDITION_OUT_OF_ENVELOPE


    def test_stale_declaration_denies(self):
        env = make_envelope()
        v = agri.check_actuation(
            envelope=env,
            declaration=make_conditions(env, declared_at=NOW - 7200),
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_CONDITION_DECLARATION_STALE


    def test_critical_wear_denies(self):
        env = make_envelope()
        v = agri.check_actuation(
            envelope=env,
            declaration=make_conditions(env, equipment_wear_class="critical"),
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_CONDITION_OUT_OF_ENVELOPE


    def test_revoked_envelope_denies(self):
        import ed25519 as _ed
        from canonical_json import jcs_sha256_hex as _h, jcs_canonical_json as _c

        env = make_envelope()
        # Revocation is terminal and receipted: the revoked state is
        # re-sealed under the authority's signature, like a fresh arming.
        bare = agri.FieldEnvelope(
            envelope_id=env.envelope_id,
            equipment_id=env.equipment_id,
            limits=env.limits,
            armed_by=env.armed_by,
            armed_at=env.armed_at,
            expires_at=env.expires_at,
            authority_pubkey_hex=env.authority_pubkey_hex,
            signature_hex="00" * 128,
            prev_digest=env.envelope_digest,
            revoked=True,
        )
        sig = _ed.sign(AUTH_SEC, _c(agri._envelope_payload(bare))).hex()
        revoked = agri.FieldEnvelope(
            envelope_id=bare.envelope_id,
            equipment_id=bare.equipment_id,
            limits=bare.limits,
            armed_by=bare.armed_by,
            armed_at=bare.armed_at,
            expires_at=bare.expires_at,
            authority_pubkey_hex=bare.authority_pubkey_hex,
            signature_hex=sig,
            prev_digest=bare.prev_digest,
            envelope_digest=_h(agri._envelope_payload(bare)),
            revoked=True,
        )
        assert agri._verify_envelope_integrity(revoked) is None
        v = agri.check_actuation(
            envelope=revoked, declaration=make_conditions(revoked), now=NOW
        )
        assert not v.allowed and v.reason == agri.DENY_ENVELOPE_REVOKED


    def test_saturated_soil_denies_regardless(self):
        env = make_envelope()
        v = agri.check_actuation(
            envelope=env,
            declaration=make_conditions(
                env, soil_state="saturated", soil_moisture_pct=50.0
            ),
            now=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_CONDITION_OUT_OF_ENVELOPE


    # -- farmer data sovereignty ---------------------------------------------


    def test_consented_data_use_allows(self):
        r = make_receipt()
        v = agri.check_data_use(
            [r], farmer_id="farmer-a", data_scope="yield",
            purpose="yield prediction", use_time=NOW,
        )
        assert v.allowed and v.receipt_id == "fdr-1"


    def test_purpose_creep_denies(self):
        r = make_receipt()
        v = agri.check_data_use(
            [r], farmer_id="farmer-a", data_scope="yield",
            purpose="credit scoring", use_time=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_DATA_PURPOSE_CREEP


    def test_revoked_receipt_denies_at_use_time(self):
        r = make_receipt()
        rev = agri.revoke_farmer_data(
            revocation_id="rev-1", receipt=r, farmer_secret=FARMER_SEC,
            revoked_at=NOW - 10,
        )
        v = agri.check_data_use(
            [r, rev], farmer_id="farmer-a", data_scope="yield",
            purpose="yield prediction", use_time=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_DATA_REVOKED


    def test_no_receipt_denies(self):
        v = agri.check_data_use(
            [], farmer_id="farmer-a", data_scope="yield",
            purpose="yield prediction", use_time=NOW,
        )
        assert not v.allowed and v.reason == agri.DENY_DATA_NO_RECEIPT


    def test_wrong_scope_uses_latest_grant_for_that_scope(self):
        r = make_receipt(receipt_id="fdr-y", data_scope="yield")
        r2 = make_receipt(receipt_id="fdr-s", data_scope="soil",
                          purpose="fertilizer recommendation")
        v = agri.check_data_use(
            [r, r2], farmer_id="farmer-a", data_scope="soil",
            purpose="fertilizer recommendation", use_time=NOW,
        )
        assert v.allowed and v.receipt_id == "fdr-s"


    # -- advice explainability -----------------------------------------------


    def test_complete_local_advice_allows(self):
        v = agri.advice_explainability_gate(FULL_ADVICE, farmer_language="swahili")
        assert v.allowed and v.classification == agri.AUTHORITATIVE_ADVICE


    def test_missing_field_non_authoritative(self):
        advice = dict(FULL_ADVICE)
        del advice["self_check"]
        v = agri.advice_explainability_gate(advice, farmer_language="swahili")
        assert not v.allowed
        assert v.classification == agri.NON_AUTHORITATIVE_ADVICE
        assert "self_check" in v.reason


    def test_language_mismatch_non_authoritative(self):
        advice = dict(FULL_ADVICE)
        advice["language"] = "english"
        v = agri.advice_explainability_gate(advice, farmer_language="swahili")
        assert not v.allowed
        assert v.reason == agri.DENY_ADVICE_LANGUAGE_MISMATCH
        assert v.classification == agri.NON_AUTHORITATIVE_ADVICE


    # -- harm ledger ----------------------------------------------------------


    def test_bad_advice_harm_event_shape(self):
        ev = agri.record_bad_advice_harm(
            advice_id="adv-1",
            scene_binding_digest=hashlib.sha256(b"bind").hexdigest(),
            model_version_digest=MODEL_D,
            input_digest=hashlib.sha256(b"img").hexdigest(),
            confidence=0.92,
            harm_description="Misdiagnosed blight; full-season loss.",
            recorded_at=NOW,
        )
        assert ev["event"] == agri.AGRI_BAD_ADVICE_HARM_EVENT
        assert ev["confidence"] == 0.92
        assert ev["recorded_at"] == NOW


    def test_bad_advice_harm_rejects_bad_confidence(self):
        with self.assertRaises(agri.AgriBoundError):
            agri.record_bad_advice_harm(
                advice_id="adv-2",
                scene_binding_digest=hashlib.sha256(b"bind").hexdigest(),
                model_version_digest=MODEL_D,
                input_digest=hashlib.sha256(b"img").hexdigest(),
                confidence=1.5,
                harm_description="x",
                recorded_at=NOW,
            )


    # -- smallholder access ----------------------------------------------------


    def test_missing_declaration_triggers_disclosure(self):
        d = agri.check_smallholder_disclosure(None, system_id="agri/advisor-1")
        assert d.disclosure_required
        assert set(d.undisclosed) == {
            "offline_capable",
            "local_language_supported",
            "low_bandwidth_mode",
        }
        assert d.disclosure_event["event"] == agri.AGRI_EXCLUSION_RISK_EVENT


    def test_partial_declaration_discloses_only_missing(self):
        decl = agri.declare_smallholder_access(
            declaration_id="sha-1",
            system_id="agri/advisor-1",
            offline_capable=True,
            local_language_supported=False,
            low_bandwidth_mode=True,
            authority_secret=AUTH_SEC,
            declared_at=NOW,
        )
        d = agri.check_smallholder_disclosure(decl, system_id="agri/advisor-1")
        assert d.disclosure_required
        assert d.undisclosed == ("local_language_supported",)


    def test_full_declaration_needs_no_disclosure(self):
        decl = agri.declare_smallholder_access(
            declaration_id="sha-2",
            system_id="agri/advisor-2",
            offline_capable=True,
            local_language_supported=True,
            low_bandwidth_mode=True,
            authority_secret=AUTH_SEC,
            declared_at=NOW,
        )
        d = agri.check_smallholder_disclosure(decl, system_id="agri/advisor-2")
        assert not d.disclosure_required
        assert d.undisclosed == ()


    def test_envelope_independence_probe(self):
        ok, reason = agri.verify_envelope_independence()
        assert ok, reason



if __name__ == "__main__":
    unittest.main()
