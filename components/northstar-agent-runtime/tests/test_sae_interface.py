"""Tests for sae_interface (sparse autoencoder interface contract)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sae_interface import (  # noqa: E402
    SAE_INTERFACE_SCHEMA,
    SAE_INTERFACE_VERSION,
    DeadFeatureReport,
    FeatureActivation,
    FeatureUsageTracker,
    SAEError,
    SparseAutoencoder,
    SparseCode,
    sae_audit_event,
)


def _sae(**kw):
    args = {"input_dim": 8, "n_features": 32, "sparsity_k": 4, "seed": 7}
    args.update(kw)
    return SparseAutoencoder(**args)


def _vec(n=8, start=0.0):
    return tuple(float(start + i) for i in range(n))


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SAE_INTERFACE_VERSION, "sae-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SAE_INTERFACE_SCHEMA, "northstar.sae-interface.v1")


class TestConstructor(unittest.TestCase):
    def test_valid(self):
        s = _sae()
        self.assertEqual((s.input_dim, s.n_features, s.sparsity_k), (8, 32, 4))

    def test_zero_dim_rejected(self):
        with self.assertRaises(ValueError):
            _sae(input_dim=0)

    def test_negative_features_rejected(self):
        with self.assertRaises(ValueError):
            _sae(n_features=-3)

    def test_bool_dim_rejected(self):
        with self.assertRaises(TypeError):
            _sae(input_dim=True)  # type: ignore[arg-type]

    def test_str_dim_rejected(self):
        with self.assertRaises(TypeError):
            _sae(n_features="32")  # type: ignore[arg-type]

    def test_k_zero_rejected(self):
        with self.assertRaises(ValueError):
            _sae(sparsity_k=0)

    def test_k_exceeds_features_rejected(self):
        with self.assertRaises(ValueError):
            _sae(n_features=4, sparsity_k=5)

    def test_bool_seed_rejected(self):
        with self.assertRaises(TypeError):
            _sae(seed=False)  # type: ignore[arg-type]

    def test_dictionary_unit_norm(self):
        s = _sae(input_dim=6, n_features=10, sparsity_k=2, seed=3)
        for j in range(10):
            col = s.decoder_vector(j)
            norm = sum(v * v for v in col) ** 0.5
            self.assertAlmostEqual(norm, 1.0, places=12)

    def test_decoder_vector_range(self):
        s = _sae()
        with self.assertRaises(ValueError):
            s.decoder_vector(32)
        with self.assertRaises(ValueError):
            s.decoder_vector(-1)
        with self.assertRaises(TypeError):
            s.decoder_vector("0")  # type: ignore[arg-type]


class TestEncode(unittest.TestCase):
    def test_exactly_k_actives(self):
        code = _sae().encode(_vec())
        self.assertEqual(len(code.actives), 4)

    def test_k_one(self):
        code = _sae(sparsity_k=1).encode(_vec())
        self.assertEqual(len(code.actives), 1)

    def test_k_equals_n_features(self):
        code = _sae(n_features=8, sparsity_k=8).encode(_vec())
        self.assertEqual(len(code.actives), 8)

    def test_values_non_negative(self):
        code = _sae().encode(tuple(-float(i) for i in range(8)))
        for a in code.actives:
            self.assertGreaterEqual(a.value, 0.0)

    def test_deterministic_same_seed(self):
        x = _vec()
        c1 = _sae(seed=11).encode(x)
        c2 = _sae(seed=11).encode(x)
        self.assertEqual(c1.feature_ids(), c2.feature_ids())
        self.assertEqual(
            [a.value for a in c1.actives], [a.value for a in c2.actives]
        )

    def test_different_seeds_likely_differ(self):
        x = _vec()
        self.assertNotEqual(
            _sae(seed=11).dictionary, _sae(seed=12).dictionary
        )

    def test_zero_vector_all_zero_values(self):
        code = _sae().encode((0.0,) * 8)
        self.assertTrue(all(a.value == 0.0 for a in code.actives))
        # tie-break: ascending feature id
        self.assertEqual(code.feature_ids(), (0, 1, 2, 3))

    def test_wrong_dim_rejected(self):
        with self.assertRaises(ValueError):
            _sae().encode((1.0,) * 7)

    def test_non_sequence_rejected(self):
        with self.assertRaises(TypeError):
            _sae().encode(42)  # type: ignore[arg-type]

    def test_str_input_rejected(self):
        with self.assertRaises(TypeError):
            _sae().encode("12345678")  # type: ignore[arg-type]

    def test_bool_element_rejected(self):
        with self.assertRaises(TypeError):
            _sae().encode((True,) + (0.0,) * 7)  # type: ignore[arg-type]

    def test_nan_rejected(self):
        with self.assertRaises(ValueError):
            _sae().encode((float("nan"),) + (0.0,) * 7)

    def test_inf_rejected(self):
        with self.assertRaises(ValueError):
            _sae().encode((float("inf"),) + (0.0,) * 7)

    def test_selection_order_descending_score(self):
        s = _sae()
        x = _vec()
        code = s.encode(x)
        scores = [
            sum(x[i] * s.decoder_vector(j)[i] for i in range(8))
            for j in code.feature_ids()
        ]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_feature_ids_unique(self):
        code = _sae().encode(_vec())
        self.assertEqual(len(set(code.feature_ids())), 4)


class TestDecode(unittest.TestCase):
    def test_decode_dim(self):
        s = _sae()
        recon = s.decode(s.encode(_vec()))
        self.assertEqual(len(recon), 8)

    def test_decode_zero_code_is_zero(self):
        s = _sae()
        code = SparseCode(
            actives=tuple(FeatureActivation(j, 0.0) for j in range(4))
        )
        self.assertEqual(s.decode(code), (0.0,) * 8)

    def test_decode_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            _sae().decode("not-a-code")  # type: ignore[arg-type]

    def test_decode_foreign_feature_id_rejected(self):
        s = _sae()
        code = SparseCode(actives=(FeatureActivation(99, 1.0),))
        with self.assertRaises(ValueError):
            s.decode(code)

    def test_reconstruction_error_non_negative(self):
        self.assertGreaterEqual(
            _sae().reconstruction_error(_vec()), 0.0
        )

    def test_reconstruction_error_finite(self):
        import math

        err = _sae().reconstruction_error(_vec(8, start=-3.0))
        self.assertTrue(math.isfinite(err))


class TestFrozenRecords(unittest.TestCase):
    def test_feature_activation_frozen(self):
        a = FeatureActivation(3, 0.5)
        with self.assertRaises(AttributeError):
            a.value = 1.0  # type: ignore[misc]

    def test_feature_activation_negative_value_rejected(self):
        with self.assertRaises(ValueError):
            FeatureActivation(0, -0.1)

    def test_sparse_code_frozen(self):
        c = SparseCode(actives=(FeatureActivation(0, 1.0),))
        with self.assertRaises(AttributeError):
            c.actives = ()  # type: ignore[misc]

    def test_sparse_code_as_dict_schema(self):
        d = SparseCode(actives=(FeatureActivation(0, 1.0),)).as_dict()
        self.assertEqual(d["schema"], SAE_INTERFACE_SCHEMA)

    def test_dead_report_frozen(self):
        r = DeadFeatureReport(dead_ids=(1, 2), total_encodes=5)
        with self.assertRaises(AttributeError):
            r.total_encodes = 6  # type: ignore[misc]

    def test_dead_report_as_dict_schema(self):
        d = DeadFeatureReport(dead_ids=(), total_encodes=0).as_dict()
        self.assertEqual(d["schema"], SAE_INTERFACE_SCHEMA)


class TestFeatureUsageTracker(unittest.TestCase):
    def test_record_and_counts(self):
        s = _sae()
        t = FeatureUsageTracker(n_features=32)
        code = s.encode(_vec())
        t.record(code)
        self.assertEqual(t.total_encodes, 1)
        counts = t.usage_counts()
        self.assertEqual(sum(counts), len([a for a in code.actives if a.value > 0]))

    def test_dead_report(self):
        t = FeatureUsageTracker(n_features=4)
        code = SparseCode(
            actives=(FeatureActivation(0, 1.0), FeatureActivation(2, 0.5))
        )
        t.record(code)
        t.record(code)
        r = t.dead_feature_report()
        self.assertEqual(r.dead_ids, (1, 3))
        self.assertEqual(r.total_encodes, 2)

    def test_zero_encodes_all_dead(self):
        t = FeatureUsageTracker(n_features=3)
        r = t.dead_feature_report()
        self.assertEqual(r.dead_ids, (0, 1, 2))
        self.assertEqual(r.total_encodes, 0)

    def test_overused_default_every_encode(self):
        t = FeatureUsageTracker(n_features=4)
        code = SparseCode(
            actives=(FeatureActivation(0, 1.0), FeatureActivation(1, 0.5))
        )
        t.record(code)
        t.record(code)
        self.assertEqual(t.overused_features(), (0, 1))

    def test_overused_threshold(self):
        t = FeatureUsageTracker(n_features=4)
        code = SparseCode(actives=(FeatureActivation(0, 1.0),))
        t.record(code)
        t.record(SparseCode(actives=(FeatureActivation(1, 1.0),)))
        self.assertEqual(t.overused_features(threshold=0.5), (0, 1))
        self.assertEqual(t.overused_features(threshold=1.0), ())

    def test_overused_zero_encodes_empty(self):
        self.assertEqual(FeatureUsageTracker(n_features=4).overused_features(), ())

    def test_overused_bad_threshold(self):
        t = FeatureUsageTracker(n_features=4)
        with self.assertRaises(ValueError):
            t.overused_features(threshold=0.0)
        with self.assertRaises(ValueError):
            t.overused_features(threshold=1.5)

    def test_record_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            FeatureUsageTracker(n_features=4).record("x")  # type: ignore[arg-type]

    def test_reset(self):
        t = FeatureUsageTracker(n_features=4)
        t.record(SparseCode(actives=(FeatureActivation(0, 1.0),)))
        t.reset()
        self.assertEqual(t.total_encodes, 0)
        self.assertEqual(t.dead_feature_report().dead_ids, (0, 1, 2, 3))


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        ev = sae_audit_event("encode", seq=2, detail={"k": 4})
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SAE_INTERFACE_SCHEMA)
        self.assertEqual(ev["event_type"], "encode")
        self.assertEqual(ev["seq"], 2)
        self.assertEqual(ev["detail"], {"k": 4})

    def test_no_detail_ok(self):
        ev = sae_audit_event("dead-feature-report", seq=0)
        self.assertNotIn("detail", ev)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            sae_audit_event("encode", seq="1")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            sae_audit_event("encode", seq=-1)

    def test_empty_event_type_rejected(self):
        with self.assertRaises(ValueError):
            sae_audit_event("", seq=0)


class TestMisc(unittest.TestCase):
    def test_as_dict_pins(self):
        d = _sae().as_dict()
        self.assertEqual(d["schema"], SAE_INTERFACE_SCHEMA)
        self.assertEqual(d["version"], SAE_INTERFACE_VERSION)
        self.assertEqual(d["sparsity_k"], 4)

    def test_main_runs(self):
        import sae_interface

        sae_interface.main()  # should not raise


if __name__ == "__main__":
    unittest.main()
