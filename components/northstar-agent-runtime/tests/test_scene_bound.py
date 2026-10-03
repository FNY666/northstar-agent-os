"""Tests for scene_bound.py (one-hundred-seventh batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""
import dataclasses
import unittest

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

from scene_bound import (
    AUTHORITATIVE_SCENE,
    CAPTURE_MODALITIES,
    CARE_SETTINGS,
    DEMOGRAPHIC_STRATA,
    DENY_BINDING_EXPIRED,
    DENY_BINDING_TAMPERED,
    DENY_CAPTURE_EXPIRED,
    DENY_CAPTURE_NO_CONSENT,
    DENY_CAPTURE_REVOKED,
    DENY_CAPTURE_SCOPE,
    DENY_DECLARATION_UNBOUND,
    DENY_MANIFEST_MISMATCH,
    DENY_OUT_OF_SCOPE,
    DENY_UNDECLARED_SCENE,
    DENY_UNKNOWN_MODEL,
    DENY_UNVALIDATED_STRATUM,
    NON_AUTHORITATIVE_SCENE,
    UNVERIFIABLE_PROCESS,
    SceneBoundError,
    authorize_capture,
    bind_model_to_scene,
    build_performance_manifest,
    capture_audit_event,
    check_model_invocation,
    check_scene_authorized,
    compute_binding_digest,
    declare_scene,
    grant_recording_consent,
    issue_binding,
    manifest_digest,
    revoke_recording_consent,
    scene_audit_event,
)


AUTH_SECRET = b"\xa1" * 32
OTHER_SECRET = b"\xb2" * 32
SUBJECT_SECRET = b"\xc3" * 32

T0 = 1_800_000_000  # fixed "now" for tests


def _manifest():
    return build_performance_manifest(
        {
            "adult_18_64": {"sensitivity": 0.846, "specificity": 0.91, "n": 3856},
            "adult_65_plus": {"sensitivity": 0.80, "specificity": 0.88, "n": 1204},
        }
    )


def _binding(pairs=None, manifest=None, secret=AUTH_SECRET, **kw):
    pairs = pairs or [("inpatient", "adult_18_64"), ("outpatient", "adult_65_plus")]
    manifest = manifest if manifest is not None else _manifest()
    args = dict(
        binding_id="bind-1",
        capability_id="aneurysm-detect",
        model_version_digest="ab" * 32,
        authorized_pairs=pairs,
        manifest=manifest,
        authority_secret=secret,
        authorized_by="dr-chen",
        authorized_at=T0 - 100,
        expires_at=T0 + 100_000,
    )
    args.update(kw)
    return issue_binding(**args)


def _declare(binding, setting="inpatient", stratum="adult_18_64", at=None):
    return declare_scene(
        declaration_id="decl-1",
        binding=binding,
        care_setting=setting,
        demographic_stratum=stratum,
        declared_at=T0 if at is None else at,
    )


class ManifestTests(unittest.TestCase):
    def test_valid_manifest(self):
        m = _manifest()
        self.assertIn("adult_18_64", m)
        self.assertEqual(m["adult_18_64"]["n"], 3856.0)

    def test_unknown_stratum_rejected(self):
        with self.assertRaises(SceneBoundError):
            build_performance_manifest(
                {"martian": {"sensitivity": 0.9, "specificity": 0.9, "n": 10}}
            )

    def test_metric_out_of_range_rejected(self):
        with self.assertRaises(SceneBoundError):
            build_performance_manifest(
                {"adult_18_64": {"sensitivity": 1.5, "specificity": 0.9, "n": 10}}
            )

    def test_empty_manifest_rejected(self):
        with self.assertRaises(SceneBoundError):
            build_performance_manifest({})

    def test_digest_is_deterministic(self):
        self.assertEqual(manifest_digest(_manifest()), manifest_digest(_manifest()))


class BindingTests(unittest.TestCase):
    def test_issue_and_recompute(self):
        b = _binding()
        self.assertEqual(compute_binding_digest(b), b.binding_digest)
        self.assertEqual(
            b.authority_pubkey_hex, ed25519.public_key(AUTH_SECRET).hex()
        )

    def test_unknown_setting_rejected(self):
        with self.assertRaises(SceneBoundError):
            _binding(pairs=[("moon_base", "adult_18_64")])

    def test_duplicate_pair_rejected(self):
        with self.assertRaises(SceneBoundError):
            _binding(
                pairs=[("inpatient", "adult_18_64"), ("inpatient", "adult_18_64")]
            )

    def test_unvalidated_stratum_never_authorized_at_issuance(self):
        # The FDA gap, fail-closed: authorizing a stratum with no
        # manifest entry raises instead of issuing.
        with self.assertRaises(SceneBoundError):
            _binding(
                pairs=[("inpatient", "pediatric")],  # pediatric not in manifest
            )

    def test_expiry_before_issue_rejected(self):
        with self.assertRaises(SceneBoundError):
            _binding(authorized_at=T0, expires_at=T0)

    def test_tampered_binding_detected(self):
        b = _binding()
        tampered = dataclasses.replace(b, authorized_by="mallory")
        v = check_scene_authorized(tampered, _declare(tampered), _manifest(), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_BINDING_TAMPERED)

    def test_wrong_authority_key_detected(self):
        b = _binding(secret=OTHER_SECRET)
        # Signature made by OTHER_SECRET but we check against the
        # pubkey embedded in the binding — consistent, so valid.
        v = check_scene_authorized(b, _declare(b), _manifest(), now=T0)
        self.assertTrue(v.allowed)
        # But a binding whose signature doesn't match its pubkey fails.
        swapped = dataclasses.replace(
            b, authority_pubkey_hex=ed25519.public_key(AUTH_SECRET).hex()
        )
        v2 = check_scene_authorized(swapped, _declare(swapped), _manifest(), now=T0)
        self.assertFalse(v2.allowed)
        self.assertEqual(v2.reason, DENY_BINDING_TAMPERED)


class GateTests(unittest.TestCase):
    def test_allow_in_scope(self):
        b = _binding()
        v = check_scene_authorized(b, _declare(b), _manifest(), now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, AUTHORITATIVE_SCENE)

    def test_undeclared_scene_denies(self):
        b = _binding()
        v = check_scene_authorized(b, None, _manifest(), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNDECLARED_SCENE)

    def test_out_of_scope_setting_denies(self):
        b = _binding()
        v = check_scene_authorized(
            b, _declare(b, setting="emergency"), _manifest(), now=T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_OUT_OF_SCOPE)

    def test_expired_binding_denies(self):
        b = _binding(expires_at=T0 - 1)
        v = check_scene_authorized(b, _declare(b), _manifest(), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_BINDING_EXPIRED)

    def test_manifest_mismatch_denies(self):
        b = _binding()
        other = build_performance_manifest(
            {
                "adult_18_64": {"sensitivity": 0.5, "specificity": 0.5, "n": 10},
                "adult_65_plus": {"sensitivity": 0.5, "specificity": 0.5, "n": 10},
            }
        )
        v = check_scene_authorized(b, _declare(b), other, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_MANIFEST_MISMATCH)

    def test_handcrafted_unvalidated_stratum_denies(self):
        # Defense in depth: even a properly signed binding that somehome
        # authorizes a stratum missing from the manifest must deny.
        b = _binding()
        small = build_performance_manifest(
            {"adult_18_64": {"sensitivity": 0.846, "specificity": 0.91, "n": 3856}}
        )
        forged = dataclasses.replace(
            b,
            authorized_pairs=(("inpatient", "adult_18_64"), ("outpatient", "pediatric")),
            manifest_digest=manifest_digest(small),
        )
        payload = {
            "binding_id": forged.binding_id,
            "capability_id": forged.capability_id,
            "model_version_digest": forged.model_version_digest,
            "authorized_pairs": [list(p) for p in forged.authorized_pairs],
            "manifest_digest": forged.manifest_digest,
            "authorized_by": forged.authorized_by,
            "authorized_at": forged.authorized_at,
            "expires_at": forged.expires_at,
            "authority_pubkey_hex": forged.authority_pubkey_hex,
            "prev_digest": forged.prev_digest,
            "schema_version": forged.schema_version,
        }
        sig = ed25519.sign(AUTH_SECRET, jcs_canonical_json(payload)).hex()
        forged = dataclasses.replace(
            forged, signature_hex=sig, binding_digest=jcs_sha256_hex(payload)
        )
        decl = declare_scene(
            declaration_id="decl-x",
            binding=forged,
            care_setting="outpatient",
            demographic_stratum="pediatric",
            declared_at=T0,
        )
        v = check_scene_authorized(forged, decl, small, now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNVALIDATED_STRATUM)

    def test_declaration_bound_to_wrong_binding_denies(self):
        b1 = _binding(binding_id="b1")
        b2 = _binding(binding_id="b2")
        v = check_scene_authorized(b1, _declare(b2), _manifest(), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_DECLARATION_UNBOUND)

    def test_declaration_from_future_denies(self):
        b = _binding()
        d = _declare(b, at=T0 + 10_000)
        v = check_scene_authorized(b, d, _manifest(), now=T0)
        self.assertFalse(v.allowed)

    def test_audit_event_shape(self):
        b = _binding()
        v = check_scene_authorized(b, _declare(b), _manifest(), now=T0)
        ev = scene_audit_event(v, action="aneurysm-detect")
        self.assertEqual(ev["event"], "scene.scene_allowed")
        self.assertEqual(ev["binding_id"], "bind-1")
        v2 = check_scene_authorized(b, None, _manifest(), now=T0)
        ev2 = scene_audit_event(v2, action="aneurysm-detect")
        self.assertEqual(ev2["event"], "scene.out_of_scope_denied")


class CaptureTests(unittest.TestCase):
    def _grant(self, **kw):
        args = dict(
            consent_id="rec-1",
            subject_id="patient-7",
            subject_secret=SUBJECT_SECRET,
            modalities=["audio"],
            purpose="clinical-documentation",
            granted_at=T0 - 50,
            expires_at=T0 + 10_000,
        )
        args.update(kw)
        return grant_recording_consent(**args)

    def test_capture_allowed_with_consent(self):
        g = self._grant()
        v = authorize_capture(
            [g],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertTrue(v.allowed)
        ev = capture_audit_event(v, subject_id="patient-7", modalities=["audio"])
        self.assertEqual(ev["event"], "scene.capture_allowed")

    def test_capture_without_consent_denies(self):
        v = authorize_capture(
            [],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CAPTURE_NO_CONSENT)

    def test_revoked_consent_denies(self):
        g = self._grant()
        r = revoke_recording_consent(
            revocation_id="rev-1",
            consent=g,
            subject_secret=SUBJECT_SECRET,
            revoked_at=T0 - 10,
        )
        v = authorize_capture(
            [g, r],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CAPTURE_REVOKED)

    def test_revocation_after_use_time_does_not_deny(self):
        g = self._grant()
        r = revoke_recording_consent(
            revocation_id="rev-1",
            consent=g,
            subject_secret=SUBJECT_SECRET,
            revoked_at=T0 + 500,
        )
        v = authorize_capture(
            [g, r],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertTrue(v.allowed)

    def test_expired_grant_denies(self):
        g = self._grant(expires_at=T0 - 1)
        v = authorize_capture(
            [g],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CAPTURE_EXPIRED)

    def test_modality_scope_mismatch_denies(self):
        g = self._grant(modalities=["audio"])
        v = authorize_capture(
            [g],
            subject_id="patient-7",
            modalities=["video"],
            purpose="clinical-documentation",
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CAPTURE_SCOPE)

    def test_purpose_mismatch_denies(self):
        g = self._grant()
        v = authorize_capture(
            [g],
            subject_id="patient-7",
            modalities=["audio"],
            purpose="marketing",
            use_time=T0,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_CAPTURE_SCOPE)

    def test_revocation_by_wrong_key_raises(self):
        g = self._grant()
        with self.assertRaises(SceneBoundError):
            revoke_recording_consent(
                revocation_id="rev-x",
                consent=g,
                subject_secret=OTHER_SECRET,
                revoked_at=T0,
            )


class ModelRegistryTests(unittest.TestCase):
    def test_invoke_in_bound_scene(self):
        b = _binding()
        reg = bind_model_to_scene({}, "aneurysm-v3", b)
        v = check_model_invocation(reg, "aneurysm-v3", _declare(b), _manifest(), now=T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, AUTHORITATIVE_SCENE)

    def test_invoke_in_unbound_scene_is_unverifiable_process(self):
        b = _binding()
        reg = bind_model_to_scene({}, "aneurysm-v3", b)
        v = check_model_invocation(
            reg, "aneurysm-v3", _declare(b, setting="emergency"), _manifest(), now=T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, UNVERIFIABLE_PROCESS)

    def test_unknown_model_denies(self):
        v = check_model_invocation({}, "ghost-v9", None, _manifest(), now=T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_UNKNOWN_MODEL)
        self.assertEqual(v.classification, UNVERIFIABLE_PROCESS)

    def test_registry_is_not_mutated(self):
        b = _binding()
        reg = {}
        reg2 = bind_model_to_scene(reg, "aneurysm-v3", b)
        self.assertEqual(reg, {})
        self.assertIn("aneurysm-v3", reg2)

    def test_rebind_replaces(self):
        b1 = _binding(binding_id="b1")
        b2 = _binding(binding_id="b2")
        reg = bind_model_to_scene({}, "m", b1)
        reg = bind_model_to_scene(reg, "m", b2)
        self.assertEqual(reg["m"].binding_id, "b2")

    def test_vocabulary_constants_sane(self):
        self.assertIn("inpatient", CARE_SETTINGS)
        self.assertIn("adult_65_plus", DEMOGRAPHIC_STRATA)
        self.assertIn("audio", CAPTURE_MODALITIES)


if __name__ == "__main__":
    unittest.main()
