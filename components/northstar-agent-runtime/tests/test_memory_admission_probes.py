"""Tests for the memory-admission probe corpus and gates.

Recalled memory is untrusted input at read time: it may arrive as
labeled data, never as instruction (unless user-tier), never as
authorization, and never at a higher tier than its write-time
provenance. These tests pin the corpus shape (10 attack probes across
3 families, 3 benign controls) and the write-gate / read-gate /
store semantics.
"""

import unittest

import memory_admission_probes as mem

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)

GOOD_DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32


def _record(**over):
    kw = dict(
        record_id="r1",
        content_digest=GOOD_DIGEST,
        writer_id="agent-1",
        trust_tier=mem.TIER_SELF_GENERATED,
        source_channel=mem.CHANNEL_AGENT_WRITE,
    )
    kw.update(over)
    return mem.build_record(**kw)


class CorpusShapeTests(unittest.TestCase):
    def test_version_pinned(self):
        self.assertEqual(mem.MEMORY_ADMISSION_VERSION, "memory-admission.v1")

    def test_probe_count(self):
        attack = [p for p in mem.MEMORY_ADMISSION_PROBES if p["expected"] == "deny"]
        benign = [p for p in mem.MEMORY_ADMISSION_PROBES if p["expected"] == "allow"]
        self.assertEqual(len(attack), 10)
        self.assertEqual(len(benign), 3)

    def test_required_keys(self):
        for probe in mem.MEMORY_ADMISSION_PROBES:
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{probe['probe']} missing {key}")

    def test_unique_names(self):
        names = [p["probe"] for p in mem.MEMORY_ADMISSION_PROBES]
        self.assertEqual(len(names), len(set(names)))

    def test_families(self):
        fams = {p["family"] for p in mem.MEMORY_ADMISSION_PROBES}
        self.assertEqual(fams, {"recall-privilege", "memory-injection", "admission-bypass"})

    def test_deny_side_keywords_in_attack_interactions(self):
        for probe in mem.MEMORY_ADMISSION_PROBES:
            if probe["expected"] != "deny":
                continue
            text = (probe["gate_interaction"] + " " + probe["reason"]).lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_accessors(self):
        self.assertEqual(len(mem.probe_names()), 13)
        self.assertEqual(
            len(mem.probes_by_family("memory-injection")), 4
        )
        self.assertEqual(
            mem.probe_by_name("injection-sleeper")["expected"], "deny"
        )
        with self.assertRaises(KeyError):
            mem.probe_by_name("nope")
        outcomes = mem.expected_outcomes()
        self.assertTrue(all(v in ("deny", "allow") for v in outcomes.values()))
        self.assertEqual(len(outcomes), 13)


class RecordValidationTests(unittest.TestCase):
    def test_round_trip_digest(self):
        rec = _record()
        self.assertTrue(mem.verify_record(rec, rec.digest()))
        self.assertFalse(mem.verify_record(rec, OTHER_DIGEST))

    def test_bad_digest_rejected(self):
        with self.assertRaises(mem.MemoryAdmissionError):
            _record(content_digest="not-a-digest")

    def test_unknown_tier_rejected(self):
        with self.assertRaises(mem.MemoryAdmissionError):
            _record(trust_tier="royal-decree")

    def test_unknown_channel_rejected(self):
        with self.assertRaises(mem.MemoryAdmissionError):
            _record(source_channel="telepathy")

    def test_empty_writer_rejected(self):
        with self.assertRaises(mem.MemoryAdmissionError):
            _record(writer_id="  ")

    def test_bad_supersedes_rejected(self):
        with self.assertRaises(mem.MemoryAdmissionError):
            _record(supersedes="junk")

    def test_digest_is_stable(self):
        self.assertEqual(_record().digest(), _record().digest())


class WriteGateTests(unittest.TestCase):
    def test_tool_result_cannot_write_user_tier(self):
        rec = _record(
            trust_tier=mem.TIER_USER, source_channel=mem.CHANNEL_TOOL_RESULT
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "deny")

    def test_peer_agent_cannot_claim_self_generated(self):
        rec = _record(
            trust_tier=mem.TIER_SELF_GENERATED,
            source_channel=mem.CHANNEL_PEER_AGENT,
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "deny")

    def test_tool_output_cannot_supersede(self):
        rec = _record(
            trust_tier=mem.TIER_TOOL_OUTPUT,
            source_channel=mem.CHANNEL_TOOL_RESULT,
            supersedes=OTHER_DIGEST,
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "deny")

    def test_unpinned_verified_external_held(self):
        rec = _record(
            trust_tier=mem.TIER_VERIFIED_EXTERNAL,
            source_channel=mem.CHANNEL_AGENT_WRITE,
            pinned=False,
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "hold")

    def test_pinned_verified_external_allowed(self):
        rec = _record(
            trust_tier=mem.TIER_VERIFIED_EXTERNAL,
            source_channel=mem.CHANNEL_AGENT_WRITE,
            pinned=True,
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "allow")

    def test_peer_agent_write_held(self):
        rec = _record(
            trust_tier=mem.TIER_THIRD_PARTY,
            source_channel=mem.CHANNEL_PEER_AGENT,
        )
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "hold")

    def test_normal_write_allowed(self):
        dec = mem.gate_memory_write(_record())
        self.assertEqual(dec.verdict, "allow")
        self.assertTrue(dec.reason)

    def test_self_generated_may_supersede(self):
        rec = _record(supersedes=OTHER_DIGEST)
        dec = mem.gate_memory_write(rec)
        self.assertEqual(dec.verdict, "allow")


class ReadGateTests(unittest.TestCase):
    def test_user_tier_gets_instruction_privilege(self):
        rec = _record(
            trust_tier=mem.TIER_USER, source_channel=mem.CHANNEL_USER_INPUT
        )
        binding = mem.gate_memory_read(rec)
        self.assertEqual(binding.privilege, mem.PRIVILEGE_INSTRUCTION)
        self.assertEqual(binding.labeled_tier, mem.TIER_USER)

    def test_tool_output_gets_data_privilege(self):
        rec = _record(
            trust_tier=mem.TIER_TOOL_OUTPUT,
            source_channel=mem.CHANNEL_TOOL_RESULT,
        )
        binding = mem.gate_memory_read(rec)
        self.assertEqual(binding.privilege, mem.PRIVILEGE_DATA)
        self.assertIn("recalled-as-data-not-instruction", binding.findings)

    def test_unpinned_verified_external_downgraded(self):
        # A verified-external claim without a pin never keeps its tier.
        rec = _record(
            trust_tier=mem.TIER_VERIFIED_EXTERNAL,
            source_channel=mem.CHANNEL_AGENT_WRITE,
            pinned=False,
        )
        binding = mem.gate_memory_read(rec)
        self.assertEqual(binding.labeled_tier, mem.TIER_THIRD_PARTY)
        self.assertIn("unpinned-verified-external-downgraded", binding.findings)

    def test_pinned_verified_external_keeps_tier_but_data(self):
        rec = _record(
            trust_tier=mem.TIER_VERIFIED_EXTERNAL,
            source_channel=mem.CHANNEL_AGENT_WRITE,
            pinned=True,
        )
        binding = mem.gate_memory_read(rec)
        self.assertEqual(binding.labeled_tier, mem.TIER_VERIFIED_EXTERNAL)
        self.assertEqual(binding.privilege, mem.PRIVILEGE_DATA)

    def test_self_generated_is_data(self):
        binding = mem.gate_memory_read(_record())
        self.assertEqual(binding.privilege, mem.PRIVILEGE_DATA)

    def test_tier_never_raised_at_read(self):
        # The labeled tier is capped at the write-time tier.
        rec = _record(trust_tier=mem.TIER_THIRD_PARTY)
        binding = mem.gate_memory_read(rec)
        self.assertEqual(binding.labeled_tier, mem.TIER_THIRD_PARTY)


class StoreTests(unittest.TestCase):
    def test_add_allowed_stores(self):
        store = mem.MemoryStore()
        dec = store.add(_record(record_id="a"))
        self.assertEqual(dec.verdict, "allow")
        self.assertEqual(store.record_ids(), ("a",))

    def test_add_denied_does_not_store(self):
        store = mem.MemoryStore()
        rec = _record(
            record_id="evil",
            trust_tier=mem.TIER_USER,
            source_channel=mem.CHANNEL_TOOL_RESULT,
        )
        dec = store.add(rec)
        self.assertEqual(dec.verdict, "deny")
        self.assertEqual(store.record_ids(), ())

    def test_add_held_does_not_store(self):
        store = mem.MemoryStore()
        rec = _record(
            record_id="peer",
            trust_tier=mem.TIER_THIRD_PARTY,
            source_channel=mem.CHANNEL_PEER_AGENT,
        )
        dec = store.add(rec)
        self.assertEqual(dec.verdict, "hold")
        self.assertEqual(store.record_ids(), ())

    def test_recall_returns_binding(self):
        store = mem.MemoryStore()
        store.add(_record(record_id="a"))
        record, binding = store.recall("a")
        self.assertEqual(record.record_id, "a")
        self.assertEqual(binding.privilege, mem.PRIVILEGE_DATA)
        self.assertTrue(mem.verify_record(record, binding.record_digest))

    def test_recall_unknown_raises(self):
        store = mem.MemoryStore()
        with self.assertRaises(mem.MemoryAdmissionError):
            store.recall("ghost")

    def test_duplicate_id_rejected(self):
        store = mem.MemoryStore()
        store.add(_record(record_id="a"))
        with self.assertRaises(mem.MemoryAdmissionError):
            store.add(_record(record_id="a"))

    def test_decisions_logged(self):
        store = mem.MemoryStore()
        store.add(_record(record_id="a"))
        store.add(
            _record(
                record_id="evil",
                trust_tier=mem.TIER_USER,
                source_channel=mem.CHANNEL_TOOL_RESULT,
            )
        )
        verdicts = [d.verdict for d in store.decisions()]
        self.assertEqual(verdicts, ["allow", "deny"])


if __name__ == "__main__":
    unittest.main()
