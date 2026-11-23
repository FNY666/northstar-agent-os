"""Tests for push_service (APNs/FCM-shaped, simulated)."""

import unittest

from push_service import (
    APNS,
    FCM,
    AUDIT_SCHEMA,
    KIND_BADGED,
    KIND_INVALID_REPORTED,
    KIND_REGISTERED,
    KIND_SENT,
    KIND_UNREGISTERED,
    MAX_PAYLOAD_BYTES,
    PUSH_SERVICE_SCHEMA,
    PUSH_SERVICE_VERSION,
    BadgeRecord,
    DuplicateTokenError,
    InvalidTokenError,
    PayloadTooLargeError,
    PushService,
    PushServiceError,
    SeqOrderError,
    SendRecord,
    TokenRecord,
    UnknownDeviceError,
    push_service_audit_event,
)


def fresh() -> PushService:
    return PushService()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(PUSH_SERVICE_VERSION, "push-service.v1")
        self.assertEqual(PUSH_SERVICE_SCHEMA, "northstar.push-service.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        ps = fresh()
        rec = ps.register("dev-1", APNS, "tok-1", 1)
        self.assertEqual(rec.version, PUSH_SERVICE_VERSION)
        self.assertEqual(rec.schema, PUSH_SERVICE_SCHEMA)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "push_service.py").read_text()
        )
        allowed = {
            "threading", "dataclasses", "typing", "__future__",
            "hashlib", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_register_happy(self):
        ps = fresh()
        rec = ps.register("dev-1", APNS, "tok-1", 1)
        self.assertIsInstance(rec, TokenRecord)
        self.assertEqual(rec.device_id, "dev-1")
        self.assertEqual(rec.platform, APNS)
        self.assertEqual(rec.push_token, "tok-1")
        self.assertFalse(rec.invalid)

    def test_register_digest_deterministic(self):
        a, b = fresh(), fresh()
        ra = a.register("dev-1", FCM, "tok-9", 1)
        rb = b.register("dev-1", FCM, "tok-9", 1)
        self.assertEqual(ra.digest, rb.digest)

    def test_register_platforms(self):
        ps = fresh()
        ps.register("dev-a", APNS, "t-a", 1)
        ps.register("dev-f", FCM, "t-f", 2)
        self.assertEqual(ps.token("dev-a").platform, APNS)
        self.assertEqual(ps.token("dev-f").platform, FCM)

    def test_register_bad_platform(self):
        ps = fresh()
        with self.assertRaises(PushServiceError):
            ps.register("dev-1", "gcm", "tok-1", 1)

    def test_register_bad_inputs(self):
        ps = fresh()
        with self.assertRaises(PushServiceError):
            ps.register("", APNS, "tok-1", 1)
        with self.assertRaises(PushServiceError):
            ps.register("dev-1", APNS, "", 1)
        with self.assertRaises(PushServiceError):
            ps.register(123, APNS, "tok-1", 1)  # type: ignore[arg-type]
        with self.assertRaises(PushServiceError):
            ps.register("dev-1", APNS, "tok-1", True)  # bool seq
        with self.assertRaises(PushServiceError):
            ps.register("dev-1", APNS, "tok-1", -1)

    def test_duplicate_token_other_device(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-shared", 1)
        with self.assertRaises(DuplicateTokenError):
            ps.register("dev-2", FCM, "tok-shared", 2)

    def test_token_refresh_releases_old_token(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-old", 1)
        ps.register("dev-1", APNS, "tok-new", 2)
        self.assertEqual(ps.token("dev-1").push_token, "tok-new")
        # The released token is now free for another device.
        ps.register("dev-2", FCM, "tok-old", 3)
        self.assertEqual(ps.token("dev-2").push_token, "tok-old")

    def test_seq_order_enforced(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 5)
        with self.assertRaises(SeqOrderError):
            ps.register("dev-2", APNS, "tok-2", 5)  # equal
        with self.assertRaises(SeqOrderError):
            ps.register("dev-2", APNS, "tok-2", 4)  # rewind


class TestUnregister(unittest.TestCase):
    def test_unregister_happy(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        rec = ps.unregister("dev-1", 2)
        self.assertEqual(rec.device_id, "dev-1")
        self.assertTrue(rec.digest.startswith("sha256:"))
        with self.assertRaises(UnknownDeviceError):
            ps.token("dev-1")

    def test_unregister_unknown(self):
        ps = fresh()
        with self.assertRaises(UnknownDeviceError):
            ps.unregister("ghost", 1)


class TestSend(unittest.TestCase):
    def _reg(self, ps, seq=1):
        return ps.register("dev-1", APNS, "tok-1", seq)

    def test_send_happy(self):
        ps = fresh()
        self._reg(ps)
        m = ps.send("dev-1", "Title", "Body", 2, badge=3, data={"k": "v"})
        self.assertIsInstance(m, SendRecord)
        self.assertEqual(m.message_id, "msg-1")
        self.assertEqual(m.title, "Title")
        self.assertEqual(m.badge, 3)
        self.assertEqual(m.data, (("k", "v"),))
        self.assertTrue(m.digest.startswith("sha256:"))

    def test_send_ids_monotonic(self):
        ps = fresh()
        self._reg(ps)
        a = ps.send("dev-1", "T", "B", 2)
        b = ps.send("dev-1", "T", "B", 3)
        self.assertEqual((a.message_id, b.message_id), ("msg-1", "msg-2"))

    def test_send_unknown_device(self):
        ps = fresh()
        with self.assertRaises(UnknownDeviceError):
            ps.send("ghost", "T", "B", 1)

    def test_send_bad_inputs(self):
        ps = fresh()
        self._reg(ps)
        with self.assertRaises(PushServiceError):
            ps.send("dev-1", "", "B", 2)
        with self.assertRaises(PushServiceError):
            ps.send("dev-1", "T", "", 2)
        with self.assertRaises(PushServiceError):
            ps.send("dev-1", "T", "B", 2, badge=True)  # bool badge
        with self.assertRaises(PushServiceError):
            ps.send("dev-1", "T", "B", 2, badge=-1)
        with self.assertRaises(PushServiceError):
            ps.send("dev-1", "T", "B", 2, data={"k": 1})  # type: ignore[dict-item]

    def test_payload_too_large(self):
        ps = fresh()
        self._reg(ps)
        huge = "x" * (MAX_PAYLOAD_BYTES + 1)
        with self.assertRaises(PayloadTooLargeError):
            ps.send("dev-1", "T", huge, 2)

    def test_message_and_messages_views(self):
        ps = fresh()
        self._reg(ps)
        a = ps.send("dev-1", "T1", "B1", 2)
        b = ps.send("dev-1", "T2", "B2", 3)
        self.assertEqual(ps.message("msg-1"), a)
        self.assertEqual(ps.messages(), (a, b))
        with self.assertRaises(PushServiceError):
            ps.message("msg-99")


class TestBadge(unittest.TestCase):
    def test_badge_happy(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        b = ps.badge("dev-1", 7, 2)
        self.assertIsInstance(b, BadgeRecord)
        self.assertEqual(b.count, 7)
        self.assertTrue(b.digest.startswith("sha256:"))

    def test_badge_unknown_device(self):
        ps = fresh()
        with self.assertRaises(UnknownDeviceError):
            ps.badge("ghost", 1, 1)

    def test_badge_bad_count(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        with self.assertRaises(PushServiceError):
            ps.badge("dev-1", -1, 2)
        with self.assertRaises(PushServiceError):
            ps.badge("dev-1", True, 2)  # type: ignore[arg-type]


class TestInvalidToken(unittest.TestCase):
    def test_report_invalid_token(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        rec = ps.report_invalid_token("tok-1", 2)
        self.assertEqual(rec.push_token, "tok-1")
        self.assertTrue(ps.token("dev-1").invalid)

    def test_send_to_invalid_token_refused(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        ps.report_invalid_token("tok-1", 2)
        with self.assertRaises(InvalidTokenError):
            ps.send("dev-1", "T", "B", 3)
        with self.assertRaises(InvalidTokenError):
            ps.badge("dev-1", 1, 4)

    def test_report_unknown_token(self):
        ps = fresh()
        with self.assertRaises(PushServiceError):
            ps.report_invalid_token("tok-nope", 1)

    def test_re_register_invalid_token_clears_flag(self):
        ps = fresh()
        ps.register("dev-1", APNS, "tok-1", 1)
        ps.report_invalid_token("tok-1", 2)
        ps.register("dev-1", APNS, "tok-1", 3)  # OS re-issued the same token
        self.assertFalse(ps.token("dev-1").invalid)
        ps.send("dev-1", "T", "B", 4)  # works again


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in (KIND_REGISTERED, KIND_UNREGISTERED, KIND_SENT,
                     KIND_BADGED, KIND_INVALID_REPORTED):
            event = push_service_audit_event(kind, 1, device_id="dev-1")
            self.assertEqual(event["kind"], kind)
            self.assertEqual(event["schema"], AUDIT_SCHEMA)
            self.assertEqual(event["module"], PUSH_SERVICE_SCHEMA)
            self.assertEqual(event["seq"], 1)

    def test_audit_unknown_kind(self):
        with self.assertRaises(PushServiceError):
            push_service_audit_event("beamed", 1)

    def test_audit_bans_token_fields(self):
        with self.assertRaises(PushServiceError):
            push_service_audit_event(KIND_REGISTERED, 1, push_token="tok-1")

    def test_audit_bad_seq(self):
        with self.assertRaises(PushServiceError):
            push_service_audit_event(KIND_SENT, -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import push_service

        push_service.main()


if __name__ == "__main__":
    unittest.main()
