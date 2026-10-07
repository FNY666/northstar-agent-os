"""Tests for identity_disclosure: disclosure rules, cards, and the log."""
import unittest

import identity_disclosure as idd
from identity_disclosure import (
    DISCLOSURE_VERSION,
    DisclosureError,
    DisclosureLog,
    DisclosureRecord,
    DisclosureRequirement,
    IdentityCard,
    disclosure_audit_events,
    disclosure_decision,
    format_disclosure,
    must_disclose,
)


def _card(**overrides):
    base = {
        "agent_name": "Northstar-1",
        "operator": "Acme Robotics",
        "capabilities_summary": "answers questions and drafts documents",
        "limitations": "cannot browse the web or make purchases",
    }
    base.update(overrides)
    return IdentityCard(**base)


class RequirementTest(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(DisclosureRequirement.ALWAYS.value, "always")
        self.assertEqual(DisclosureRequirement.ON_REQUEST.value, "on_request")
        self.assertEqual(DisclosureRequirement.NEVER.value, "never")

    def test_three_members(self):
        self.assertEqual(len(list(DisclosureRequirement)), 3)


class MustDiscloseTest(unittest.TestCase):
    def test_chat_is_user_facing(self):
        self.assertTrue(must_disclose("chat"))

    def test_email_is_user_facing(self):
        self.assertTrue(must_disclose("email"))

    def test_voice_is_user_facing(self):
        self.assertTrue(must_disclose("voice"))

    def test_phone_sms_social_are_user_facing(self):
        for channel in ("phone", "sms", "social", "messaging", "video"):
            with self.subTest(channel=channel):
                self.assertTrue(must_disclose(channel))

    def test_api_is_not_user_facing(self):
        self.assertFalse(must_disclose("api"))

    def test_internal_batch_system_are_not_user_facing(self):
        for channel in ("internal", "batch", "system"):
            with self.subTest(channel=channel):
                self.assertFalse(must_disclose(channel))

    def test_unknown_channel_fails_closed_toward_disclosure(self):
        self.assertTrue(must_disclose("holodeck"))
        self.assertTrue(must_disclose(""))
        self.assertTrue(must_disclose(None))

    def test_case_and_whitespace_insensitive(self):
        self.assertTrue(must_disclose("  Chat "))
        self.assertFalse(must_disclose(" API "))


class DisclosureDecisionTest(unittest.TestCase):
    def test_user_facing_overrides_never(self):
        # The context rule is a floor: NEVER cannot silence a user-facing channel.
        self.assertTrue(
            disclosure_decision(DisclosureRequirement.NEVER, "chat")
        )

    def test_always_discloses_on_internal_channel(self):
        self.assertTrue(
            disclosure_decision(DisclosureRequirement.ALWAYS, "api")
        )

    def test_on_request_discloses_only_when_asked(self):
        self.assertTrue(
            disclosure_decision(
                DisclosureRequirement.ON_REQUEST, "api", on_request=True
            )
        )
        self.assertFalse(
            disclosure_decision(
                DisclosureRequirement.ON_REQUEST, "api", on_request=False
            )
        )

    def test_never_stays_silent_on_internal_channel(self):
        self.assertFalse(
            disclosure_decision(DisclosureRequirement.NEVER, "internal")
        )

    def test_bad_requirement_raises(self):
        with self.assertRaises(DisclosureError):
            disclosure_decision("always", "chat")


class IdentityCardTest(unittest.TestCase):
    def test_builds_with_valid_fields(self):
        card = _card()
        self.assertEqual(card.agent_name, "Northstar-1")
        self.assertEqual(card.operator, "Acme Robotics")

    def test_rejects_empty_agent_name(self):
        with self.assertRaises(DisclosureError):
            _card(agent_name="   ")

    def test_rejects_empty_limitations(self):
        with self.assertRaises(DisclosureError):
            _card(limitations="")

    def test_rejects_non_string(self):
        with self.assertRaises(DisclosureError):
            _card(operator=None)

    def test_frozen(self):
        card = _card()
        with self.assertRaises(Exception):
            card.agent_name = "other"

    def test_digest_is_stable_and_64_hex(self):
        first, second = _card().digest(), _card().digest()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        int(first, 16)

    def test_digest_changes_with_content(self):
        self.assertNotEqual(_card().digest(), _card(limitations="other").digest())

    def test_as_dict_carries_version(self):
        self.assertEqual(_card().as_dict()["version"], DISCLOSURE_VERSION)


class FormatDisclosureTest(unittest.TestCase):
    def test_names_agent_as_ai_agent(self):
        text = format_disclosure(_card())
        self.assertIn("Northstar-1", text)
        self.assertIn("AI agent", text)

    def test_names_operator_capabilities_limitations(self):
        text = format_disclosure(_card())
        self.assertIn("Acme Robotics", text)
        self.assertIn("answers questions", text)
        self.assertIn("cannot browse the web", text)

    def test_rejects_non_card(self):
        with self.assertRaises(DisclosureError):
            format_disclosure({"agent_name": "x"})


class DisclosureRecordTest(unittest.TestCase):
    def test_rejects_negative_seq(self):
        with self.assertRaises(DisclosureError):
            DisclosureRecord(
                seq=-1,
                agent_name="a",
                context="chat",
                card_digest="0" * 64,
            )

    def test_rejects_bool_seq(self):
        with self.assertRaises(DisclosureError):
            DisclosureRecord(
                seq=True,
                agent_name="a",
                context="chat",
                card_digest="0" * 64,
            )

    def test_rejects_bad_digest(self):
        with self.assertRaises(DisclosureError):
            DisclosureRecord(
                seq=0, agent_name="a", context="chat", card_digest="zzz"
            )

    def test_record_digest_chains(self):
        card = _card()
        first = DisclosureRecord(
            seq=0, agent_name="a", context="chat", card_digest=card.digest()
        )
        second = DisclosureRecord(
            seq=1,
            agent_name="a",
            context="chat",
            card_digest=card.digest(),
            prev_digest=first.record_digest(),
        )
        self.assertEqual(second.prev_digest, first.record_digest())


class DisclosureLogTest(unittest.TestCase):
    def test_disclose_returns_record_and_text(self):
        log = DisclosureLog()
        record, text = log.disclose(_card(), "chat", seq=0)
        self.assertIsInstance(record, DisclosureRecord)
        self.assertIn("Northstar-1", text)
        self.assertEqual(len(log), 1)

    def test_append_enforces_chain_continuity(self):
        log = DisclosureLog()
        card = _card()
        log.disclose(card, "chat", seq=0)
        bad = DisclosureRecord(
            seq=1,
            agent_name=card.agent_name,
            context="chat",
            card_digest=card.digest(),
            prev_digest="f" * 64,
        )
        with self.assertRaises(DisclosureError):
            log.append(bad)

    def test_append_rejects_backwards_seq(self):
        log = DisclosureLog()
        card = _card()
        log.disclose(card, "chat", seq=5)
        tail = log.records()[-1]
        bad = DisclosureRecord(
            seq=4,
            agent_name=card.agent_name,
            context="chat",
            card_digest=card.digest(),
            prev_digest=tail.record_digest(),
        )
        with self.assertRaises(DisclosureError):
            log.append(bad)

    def test_first_record_must_chain_from_zero(self):
        log = DisclosureLog()
        card = _card()
        bad = DisclosureRecord(
            seq=0,
            agent_name=card.agent_name,
            context="chat",
            card_digest=card.digest(),
            prev_digest="1" * 64,
        )
        with self.assertRaises(DisclosureError):
            log.append(bad)

    def test_records_for_filters_by_agent(self):
        log = DisclosureLog()
        log.disclose(_card(agent_name="a1"), "chat", seq=0)
        log.disclose(_card(agent_name="a2"), "email", seq=1)
        log.disclose(_card(agent_name="a1"), "voice", seq=2)
        self.assertEqual(len(log.records_for("a1")), 2)
        self.assertEqual(len(log.records_for("a2")), 1)
        self.assertEqual(log.records_for("a1")[0].context, "chat")

    def test_verify_chain_passes_on_healthy_log(self):
        log = DisclosureLog()
        for i, channel in enumerate(("chat", "email", "voice")):
            log.disclose(_card(), channel, seq=i)
        self.assertTrue(log.verify_chain())

    def test_log_is_append_only_no_mutation_api(self):
        log = DisclosureLog()
        log.disclose(_card(), "chat", seq=0)
        self.assertFalse(hasattr(log, "delete"))
        self.assertFalse(hasattr(log, "rewrite"))
        records = log.records()
        with self.assertRaises(Exception):
            records[0] = None

    def test_disclose_rejects_non_card(self):
        log = DisclosureLog()
        with self.assertRaises(DisclosureError):
            log.disclose("not-a-card", "chat", seq=0)

    def test_restart_continuity(self):
        # A fresh log object rebuilt from prior records continues the chain.
        log = DisclosureLog()
        card = _card()
        log.disclose(card, "chat", seq=0)
        log.disclose(card, "email", seq=1)
        rebuilt = DisclosureLog()
        for record in log.records():
            rebuilt.append(record)
        self.assertTrue(rebuilt.verify_chain())
        rec, _ = rebuilt.disclose(card, "voice", seq=2)
        self.assertEqual(rec.prev_digest, log.records()[-1].record_digest())
        self.assertTrue(rebuilt.verify_chain())


class AuditEventsTest(unittest.TestCase):
    def test_event_pins_agent_channel_and_digests(self):
        log = DisclosureLog()
        record, _ = log.disclose(_card(), "chat", seq=0)
        events = disclosure_audit_events(record, note="hello")
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event"], "identity_disclosure.disclosed")
        self.assertEqual(event["agent_name"], "Northstar-1")
        self.assertEqual(event["context"], "chat")
        self.assertEqual(event["card_digest"], record.card_digest)
        self.assertEqual(event["record_digest"], record.record_digest())
        self.assertEqual(event["note"], "hello")

    def test_rejects_non_record(self):
        with self.assertRaises(DisclosureError):
            disclosure_audit_events("nope")


if __name__ == "__main__":
    unittest.main()
