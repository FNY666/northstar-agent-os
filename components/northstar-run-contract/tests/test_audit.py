"""The audit NDJSON v1 envelope: strict, versioned, round-trippable."""
import unittest

from audit import (
    AUDIT_SCHEMA_VERSION,
    dumps_record,
    iter_ndjson,
    new_record,
    now_rfc3339,
    rfc3339_from_epoch,
    to_ndjson,
    validate_record,
)


def sample(**overrides):
    record = new_record(
        "northstar-agent-runtime",
        "tool_result",
        seq=3,
        ts="2026-09-07T03:04:05.123Z",
        level="info",
        payload={"tool": "Read", "ok": True},
        session_id="ns-20260907T000000Z-abcdef01",
    )
    record.update(overrides)
    return record


class EnvelopeTests(unittest.TestCase):
    def test_sample_record_is_valid_and_canonical(self):
        record = sample()
        self.assertEqual(validate_record(record), ())
        line = dumps_record(record)
        self.assertEqual(line, '{"component":"northstar-agent-runtime","event":"tool_result","level":"info","payload":{"ok":true,"tool":"Read"},"schema_version":"audit.ndjson/1","seq":3,"session_id":"ns-20260907T000000Z-abcdef01","ts":"2026-09-07T03:04:05.123Z"}')

    def test_required_fields_are_enforced(self):
        for key in ("schema_version", "component", "event", "ts", "level", "payload"):
            with self.subTest(missing=key):
                record = sample()
                del record[key]
                self.assertTrue(
                    any(f"missing {key!r}" in error for error in validate_record(record)),
                    f"expected a missing-field error for {key!r}: {validate_record(record)}",
                )

    def test_unknown_envelope_fields_are_rejected_fail_closed(self):
        record = sample(extra="sneaky")
        errors = validate_record(record)
        self.assertIn("unknown audit envelope fields: extra", errors)

    def test_schema_version_is_a_hard_version_gate(self):
        record = sample(schema_version="audit.ndjson/2")
        self.assertIn("unsupported audit schema_version", validate_record(record)[0])

    def test_levels_ts_component_and_ids_are_validated(self):
        self.assertIn("must be one of", validate_record(sample(level="loud"))[0])
        self.assertIn("must be an RFC 3339", validate_record(sample(ts="2026-09-07"))[0])
        self.assertIn("must be an RFC 3339", validate_record(sample(ts="2026-09-07T03:04:05.123+08:00"))[0])
        self.assertIn("lowercase", validate_record(sample(component="Northstar"))[0])
        self.assertIn("identifier", validate_record(sample(event=""))[0])
        self.assertIn("non-negative integer", validate_record(sample(seq=-1))[0])
        self.assertIn("at most 200", validate_record(sample(actor_id="x" * 201))[0])

    def test_payload_must_be_an_object(self):
        record = sample()
        record["payload"] = ["not", "an", "object"]
        self.assertIn("must be dict", validate_record(record)[0])


class TimestampTests(unittest.TestCase):
    def test_now_rfc3339_is_utc_with_millis_and_z(self):
        stamp = now_rfc3339(now=1_752_000_000.25)
        self.assertEqual(stamp, "2025-07-08T18:40:00.250Z")
        stamp = now_rfc3339()
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_epoch_seconds_convert_to_utc_rfc3339(self):
        self.assertEqual(rfc3339_from_epoch(0), "1970-01-01T00:00:00.000Z")
        self.assertEqual(rfc3339_from_epoch(1_752_000_000), "2025-07-08T18:40:00.000Z")

    def test_second_precision_ts_is_accepted_too(self):
        self.assertEqual(validate_record(sample(ts="2026-09-07T03:04:05Z")), ())


class NdjsonTests(unittest.TestCase):
    def test_to_ndjson_and_iter_round_trip(self):
        first = sample(seq=1)
        second = sample(seq=2, event="denial", level="error", payload={"tool": "Write"})
        text = to_ndjson([first, second])
        self.assertTrue(text.endswith("\n"))
        parsed = list(iter_ndjson(text.splitlines()))
        self.assertEqual(parsed, [first, second])

    def test_iter_skips_blank_lines_and_names_damage(self):
        text = to_ndjson([sample(seq=1)])
        self.assertEqual(list(iter_ndjson(["\n", text, "  \n"])), [sample(seq=1)])
        with self.assertRaises(ValueError) as caught:
            list(iter_ndjson(["not json", to_ndjson([sample(seq=1)])]))
        self.assertIn("line 1", str(caught.exception))
        with self.assertRaises(ValueError) as caught:
            list(iter_ndjson(['{"schema_version":"audit.ndjson/9"}']))
        self.assertIn("line 1", str(caught.exception))

    def test_dumps_rejects_invalid_records(self):
        with self.assertRaises(ValueError):
            dumps_record({"schema_version": "audit.ndjson/1"})


def provenance(**overrides):
    """A valid SLSA v1.0-style provenance object for tests."""
    base = {
        "buildType": "https://northstar.dev/agent-run/v1",
        "builder": {"id": "https://northstar.dev/runtime/northstar-agent-runtime"},
        "invocationId": "run-1",
        "externalParameters": {"tool": "Write", "args": {"path": "/tmp/x"}},
        "externalParametersTrust": "untrusted",
        "internalParameters": {"approval_tier": 3},
        "resolvedDependencies": [
            {"uri": "tool://Write", "digest": {"sha256": "ab" * 32}},
        ],
        "selfAsserted": True,
    }
    base.update(overrides)
    return base


class ProvenanceTests(unittest.TestCase):
    def test_valid_provenance_passes_and_round_trips(self):
        record = sample(provenance=provenance(), run_id="run-1")
        self.assertEqual(validate_record(record), ())
        line = dumps_record(record)
        reparsed = next(iter_ndjson([line]))
        self.assertEqual(reparsed["provenance"]["externalParametersTrust"], "untrusted")

    def test_new_record_accepts_provenance(self):
        record = new_record(
            "northstar-agent-runtime", "tool_call",
            ts="2026-09-07T03:04:05.123Z", run_id="run-9",
            provenance=provenance(invocationId="run-9"),
        )
        self.assertEqual(validate_record(record), ())

    def test_provenance_is_optional(self):
        self.assertEqual(validate_record(sample()), ())

    def test_unmarked_external_parameters_fail_closed(self):
        bad = provenance()
        del bad["externalParametersTrust"]
        errors = validate_record(sample(provenance=bad))
        self.assertTrue(
            any("externalParametersTrust" in e for e in errors),
            f"expected a trust-marking error: {errors}",
        )

    def test_invalid_trust_value_is_rejected(self):
        bad = provenance(externalParametersTrust="probably-fine")
        errors = validate_record(sample(provenance=bad))
        self.assertTrue(any("externalParametersTrust" in e for e in errors))

    def test_empty_external_parameters_need_no_marking(self):
        # No external inputs, nothing to mark.
        ok = provenance(externalParameters={})
        del ok["externalParametersTrust"]
        self.assertEqual(validate_record(sample(provenance=ok)), ())

    def test_verified_external_parameters_pass(self):
        ok = provenance(externalParametersTrust="verified")
        self.assertEqual(validate_record(sample(provenance=ok)), ())

    def test_invocation_id_must_match_run_id(self):
        bad = provenance(invocationId="run-OTHER")
        errors = validate_record(sample(provenance=bad, run_id="run-1"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_invocation_id_matching_run_id_passes(self):
        self.assertEqual(validate_record(sample(provenance=provenance(), run_id="run-1")), ())

    def test_unknown_provenance_fields_are_rejected(self):
        bad = provenance(sneaky="field")
        errors = validate_record(sample(provenance=bad))
        self.assertIn("unknown provenance fields: sneaky", errors)

    def test_malformed_dependencies_are_rejected(self):
        bad = provenance(resolvedDependencies=[{"uri": "", "digest": {}}])
        errors = validate_record(sample(provenance=bad))
        self.assertTrue(any("resolvedDependencies[0]" in e for e in errors), errors)

    def test_builder_id_must_be_non_empty(self):
        bad = provenance(builder={"id": ""})
        errors = validate_record(sample(provenance=bad))
        self.assertTrue(any("builder.id" in e for e in errors), errors)

    def test_new_record_rejects_unmarked_external_parameters(self):
        with self.assertRaises(ValueError):
            bad = provenance()
            del bad["externalParametersTrust"]
            new_record(
                "northstar-agent-runtime", "tool_call",
                ts="2026-09-07T03:04:05.123Z", provenance=bad,
            )


if __name__ == "__main__":
    unittest.main()
