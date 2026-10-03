"""Harness integrity binding (ninetieth batch).

Covers ``harness_binding.py``:
- The harness hash is deterministic, canonical (order-independent), and
  64 hex chars.
- Audit binding pins the digest with the right event name.
- Verification passes on the intact config and fails on any tamper
  (prompt template, tool version, environment, code version).
- Malformed pins fail closed (raise) instead of comparing False.
- Scores render only as the quad; the bare-score API refuses.
- ``invalidate_if_tampered`` is one-way: tampered stays invalid.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

import harness_binding
from harness_binding import (
    BoundScore,
    HarnessBindingError,
    HarnessConfig,
    ScoredResult,
    bind_harness_to_audit,
    bind_score,
    canonical_harness_bytes,
    emit_bare_score,
    format_quad,
    harness_hash,
    invalidate_if_tampered,
    validate_quad,
    verify_harness_binding,
)


def _config(**overrides) -> HarnessConfig:
    base = dict(
        code_version="northstar.governance.bench.v13",
        prompt_templates=(("grader", "a" * 64), ("judge", "b" * 64)),
        tool_versions=(("Shell", "1.0"), ("Read", "2.3")),
        environment=(("python", "3.12"), ("platform", "linux")),
    )
    base.update(overrides)
    return HarnessConfig(**base)


def _result(config: HarnessConfig) -> ScoredResult:
    return ScoredResult(
        model_version="test-model-2026-10",
        harness=config,
        effort="medium",
        cost_per_task_usd=0.42,
        score=0.85,
        n_tasks=40,
    )


class TestHarnessHash(unittest.TestCase):
    def test_hash_is_deterministic_64_hex(self) -> None:
        digest = harness_hash(_config())
        self.assertEqual(digest, harness_hash(_config()))
        self.assertEqual(len(digest), 64)
        int(digest, 16)

    def test_hash_is_order_independent(self) -> None:
        a = _config(tool_versions=(("Shell", "1.0"), ("Read", "2.3")))
        b = _config(tool_versions=(("Read", "2.3"), ("Shell", "1.0")))
        self.assertEqual(harness_hash(a), harness_hash(b))
        self.assertEqual(canonical_harness_bytes(a), canonical_harness_bytes(b))

    def test_any_field_change_moves_the_hash(self) -> None:
        intact = harness_hash(_config())
        variants = [
            _config(code_version="northstar.governance.bench.v14"),
            _config(prompt_templates=(("grader", "c" * 64), ("judge", "b" * 64))),
            _config(tool_versions=(("Shell", "1.1"), ("Read", "2.3"))),
            _config(environment=(("python", "3.13"), ("platform", "linux"))),
        ]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotEqual(harness_hash(variant), intact)

    def test_rejects_non_config(self) -> None:
        with self.assertRaises(HarnessBindingError):
            canonical_harness_bytes({"code_version": "x"})  # type: ignore[arg-type]


class TestAuditBinding(unittest.TestCase):
    def test_audit_record_pins_digest(self) -> None:
        config = _config()
        record = bind_harness_to_audit(config, model_version="m-1", note="n")
        self.assertEqual(record["event"], "harness_binding.bound")
        self.assertEqual(record["harness_sha256"], harness_hash(config))
        self.assertEqual(record["model_version"], "m-1")
        self.assertEqual(record["schema"], harness_binding.HARNESS_BINDING_SCHEMA_VERSION)

    def test_audit_binding_rejects_empty_model(self) -> None:
        with self.assertRaises(HarnessBindingError):
            bind_harness_to_audit(_config(), model_version="")

    def test_verify_passes_on_intact_config(self) -> None:
        config = _config()
        self.assertTrue(verify_harness_binding(config, harness_hash(config)))

    def test_verify_fails_on_tampered_config(self) -> None:
        config = _config()
        pinned = harness_hash(config)
        tampered = _config(prompt_templates=(("grader", "f" * 64), ("judge", "b" * 64)))
        self.assertFalse(verify_harness_binding(tampered, pinned))

    def test_verify_fails_closed_on_malformed_pin(self) -> None:
        config = _config()
        for bad in ("", "xyz", "a" * 63, "a" * 65, "z" * 64, None):
            with self.subTest(bad=bad):
                with self.assertRaises(HarnessBindingError):
                    verify_harness_binding(config, bad)  # type: ignore[arg-type]


class TestQuad(unittest.TestCase):
    def test_format_quad_carries_all_four_axes(self) -> None:
        config = _config()
        rendered = format_quad(_result(config))
        self.assertIn("score=0.8500", rendered)
        self.assertIn("model=test-model-2026-10", rendered)
        self.assertIn("harness=sha256:" + harness_hash(config), rendered)
        self.assertIn("effort=medium", rendered)
        self.assertIn("cost=$0.4200/task", rendered)

    def test_bare_score_is_refused(self) -> None:
        with self.assertRaises(HarnessBindingError):
            emit_bare_score(_result(_config()))

    def test_validate_quad_rejects_incomplete(self) -> None:
        config = _config()
        good = _result(config)
        cases = [
            ScoredResult("", config, "medium", 0.42, 0.85),
            ScoredResult("m", config, "extreme", 0.42, 0.85),
            ScoredResult("m", config, "medium", -0.01, 0.85),
            ScoredResult("m", config, "medium", 0.42, 1.5),
            ScoredResult("m", config, "medium", 0.42, -0.1),
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(HarnessBindingError):
                    validate_quad(bad)
        with self.assertRaises(HarnessBindingError):
            validate_quad("not-a-result")  # type: ignore[arg-type]
        # The good one passes validation.
        validate_quad(good)

    def test_zero_cost_is_allowed(self) -> None:
        result = ScoredResult("m", _config(), "low", 0.0, 0.5)
        validate_quad(result)
        self.assertIn("cost=$0.0000/task", format_quad(result))


class TestInvalidation(unittest.TestCase):
    def test_intact_harness_stays_valid(self) -> None:
        config = _config()
        bound = bind_score(_result(config), config)
        self.assertEqual(bound.state, "valid")
        again = invalidate_if_tampered(bound, config)
        self.assertEqual(again.state, "valid")

    def test_tampered_harness_invalidates(self) -> None:
        config = _config()
        bound = bind_score(_result(config), config)
        tampered = _config(tool_versions=(("Shell", "9.9"), ("Read", "2.3")))
        invalid = invalidate_if_tampered(bound, tampered)
        self.assertEqual(invalid.state, "invalid")
        self.assertTrue(invalid.reason)

    def test_invalidation_is_one_way(self) -> None:
        config = _config()
        bound = bind_score(_result(config), config)
        tampered = _config(tool_versions=(("Shell", "9.9"), ("Read", "2.3")))
        invalid = invalidate_if_tampered(bound, tampered)
        # Restoring the original config does NOT revive the score.
        revived = invalidate_if_tampered(invalid, config)
        self.assertEqual(revived.state, "invalid")

    def test_bind_score_validates_quad(self) -> None:
        config = _config()
        bad = ScoredResult("", config, "medium", 0.42, 0.85)
        with self.assertRaises(HarnessBindingError):
            bind_score(bad, config)


if __name__ == "__main__":
    unittest.main()
