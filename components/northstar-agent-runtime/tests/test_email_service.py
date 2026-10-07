"""Unit tests for email_service.py (email-service.v1)."""

import sys
import unittest

sys.path.insert(0, "..")
import email_service as es


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(es.VERSION, "email-service.v1")
        self.assertEqual(es.SCHEMA, "northstar.email-service.v1")


class TestSend(unittest.TestCase):
    def test_send_roundtrip(self):
        svc = es.EmailService()
        m = svc.send("alice@example.com", "Hi", "body", 1,
                     sender="noreply@agents.dev", template_id="t.v1")
        self.assertEqual(m.id, "msg-1")
        self.assertTrue(m.digest.startswith("sha256:"))
        self.assertEqual(svc.message("msg-1").recipient, "alice@example.com")

    def test_digest_determinism(self):
        def mk(seq_base):
            svc = es.EmailService()
            return svc.send("a@x.com", "S", "B", seq_base,
                            sender="n@y.com", template_id="t.v1").digest
        self.assertEqual(mk(1), mk(1))

    def test_bad_addresses(self):
        svc = es.EmailService()
        for i, bad in enumerate(("not-an-email", "a@b", "", None, 123)):
            with self.assertRaises(es.InvalidAddressError, msg=repr(bad)):
                svc.send(bad, "S", "B", 10 + i)

    def test_empty_subject_body(self):
        svc = es.EmailService()
        with self.assertRaises(es.EmptyFieldError):
            svc.send("a@x.com", "   ", "B", 1)
        with self.assertRaises(es.EmptyFieldError):
            svc.send("a@x.com", "S", "", 2)

    def test_seq_order(self):
        svc = es.EmailService()
        svc.send("a@x.com", "S", "B", 1)
        with self.assertRaises(es.SeqOrderError):
            svc.send("a@x.com", "S", "B", 1)
        with self.assertRaises(es.SeqOrderError):
            svc.send("a@x.com", "S", "B", True)


class TestTrack(unittest.TestCase):
    def _svc_msg(self, seq=1):
        svc = es.EmailService()
        m = svc.send("a@x.com", "S", "B", seq)
        return svc, m

    def test_track_happy(self):
        svc, m = self._svc_msg()
        ev = svc.track(m.id, "sent", 2)
        self.assertEqual(ev.id, "ev-1")
        self.assertEqual(ev.message_id, m.id)
        self.assertTrue(ev.digest.startswith("sha256:"))

    def test_unknown_message(self):
        svc, m = self._svc_msg()
        with self.assertRaises(es.UnknownMessageError):
            svc.track("msg-999", "sent", 2)

    def test_unknown_kind(self):
        svc, m = self._svc_msg()
        with self.assertRaises(es.InvalidEventError):
            svc.track(m.id, "faxed", 2)

    def test_bad_transition(self):
        svc, m = self._svc_msg()
        svc.track(m.id, "sent", 2)
        svc.track(m.id, "delivered", 3)
        svc.track(m.id, "opened", 4)
        with self.assertRaises(es.BadTransitionError):
            svc.track(m.id, "delivered", 5)

    def test_idempotency_replay(self):
        svc, m = self._svc_msg()
        e1 = svc.track(m.id, "sent", 2, idempotency_key="k-1")
        e2 = svc.track(m.id, "sent", 3, idempotency_key="k-1")
        self.assertEqual(e1.id, e2.id)

    def test_idempotency_mismatch(self):
        svc, m = self._svc_msg()
        svc.track(m.id, "sent", 2, idempotency_key="k-1")
        with self.assertRaises(es.IdempotencyMismatchError):
            svc.track(m.id, "delivered", 3, idempotency_key="k-1")

    def test_events_view(self):
        svc, m = self._svc_msg()
        self.assertEqual(svc.events(m.id), ())
        svc.track(m.id, "sent", 2)
        self.assertEqual(len(svc.events(m.id)), 1)


class TestBounce(unittest.TestCase):
    def test_hard_bounce_suppresses(self):
        svc = es.EmailService()
        m = svc.send("bob@example.com", "S", "B", 1)
        b = svc.bounce(m.id, "hard", "mailbox-not-found", 2)
        self.assertEqual(b.kind, "hard")
        self.assertTrue(svc.is_suppressed("bob@example.com"))
        self.assertEqual(svc.bounce_for(m.id).id, b.id)

    def test_suppressed_send_refused(self):
        svc = es.EmailService()
        m = svc.send("bob@example.com", "S", "B", 1)
        svc.bounce(m.id, "hard", "gone", 2)
        with self.assertRaises(es.SuppressedRecipientError):
            svc.send("bob@example.com", "S2", "B2", 3)

    def test_soft_bounce_no_suppress(self):
        svc = es.EmailService()
        m = svc.send("carol@example.com", "S", "B", 1)
        svc.bounce(m.id, "soft", "mailbox-full", 2)
        self.assertFalse(svc.is_suppressed("carol@example.com"))

    def test_double_bounce_refused(self):
        svc = es.EmailService()
        m = svc.send("d@example.com", "S", "B", 1)
        svc.bounce(m.id, "soft", "full", 2)
        with self.assertRaises(es.AlreadyBouncedError):
            svc.bounce(m.id, "soft", "full", 3)

    def test_statuses(self):
        svc = es.EmailService()
        m1 = svc.send("a@x.com", "S", "B", 1)
        self.assertEqual(svc.status(m1.id), "sent")
        svc.track(m1.id, "sent", 2)
        self.assertEqual(svc.status(m1.id), "in-flight")
        m2 = svc.send("e@x.com", "S", "B", 3)
        svc.bounce(m2.id, "hard", "gone", 4)
        self.assertEqual(svc.status(m2.id), "bounced")
        with self.assertRaises(es.UnknownMessageError):
            svc.status("msg-404")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        svc = es.EmailService()
        m = svc.send("a@x.com", "S", "B", 1)
        for kind, ref in (
            ("message-queued", m.id),
            ("event-tracked", "ev-1"),
            ("bounced", "bn-1"),
            ("rejected", "msg-1"),
        ):
            ev = es.email_service_audit_event(kind, ref, m.digest, 1)
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "northstar.email-service.v1")
        with self.assertRaises(es.EmailError):
            es.email_service_audit_event("nope", "x", "d", 1)

    def test_main_selfcheck(self):
        es.main()


if __name__ == "__main__":
    unittest.main()
