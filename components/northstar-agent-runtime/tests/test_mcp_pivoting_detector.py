"""Tests for mcp_pivoting_detector: SSRF protocol-pivoting checkpoint."""
from __future__ import annotations

import unittest

from mcp_pivoting_detector import (
    MCP_PIVOTING_VERSION,
    SCHEMA_PIN,
    PivotingAttempt,
    check_tool_call,
    detect_pivoting,
    inspect_tool_call,
)


def call(tool="fetch", url=None, **extra):
    args = {"tool": tool}
    if url is not None:
        args["url"] = url
    args.update(extra)
    return args


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MCP_PIVOTING_VERSION, "mcp-pivoting-detector.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.mcp-pivoting-detector.v1")


class TestMetadataEndpoints(unittest.TestCase):
    def test_aws_metadata_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://169.254.169.254/latest/meta-data/")))

    def test_gcp_metadata_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://metadata.google.internal/computeMetadata/v1/")))

    def test_alibaba_metadata_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://100.100.100.200/latest/meta-data/")))

    def test_metadata_reason_vocabulary(self):
        rec = inspect_tool_call(call(url="http://169.254.169.254/"))
        self.assertTrue(rec.blocked)
        self.assertEqual(rec.reason, "metadata-endpoint")


class TestLoopback(unittest.TestCase):
    def test_localhost_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://localhost:8080/admin")))

    def test_loopback_ip_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://127.0.0.1:9000/")))

    def test_loopback_reason_vocabulary(self):
        rec = inspect_tool_call(call(url="http://localhost/"))
        self.assertEqual(rec.reason, "loopback")

    def test_decimal_loopback_spelling_blocked(self):
        # 2130706433 == 127.0.0.1
        self.assertTrue(detect_pivoting(call(url="http://2130706433/")))

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://[::ffff:127.0.0.1]/")))

    def test_hex_and_octal_loopback_spellings_blocked(self):
        for host in ("0x7f000001", "017700000001", "0x7f.1"):
            with self.subTest(host=host):
                self.assertTrue(detect_pivoting(call(url=f"http://{host}/")))


class TestPrivateRanges(unittest.TestCase):
    def test_rfc1918_10_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://10.0.0.5/internal")))

    def test_rfc1918_192_168_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://192.168.1.1/")))

    def test_rfc1918_172_16_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://172.20.4.9:8080/")))

    def test_internal_ip_reason_vocabulary(self):
        rec = inspect_tool_call(call(url="http://10.1.2.3/"))
        self.assertEqual(rec.reason, "internal-ip")

    def test_ipv4_mapped_ipv6_metadata_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://[::ffff:169.254.169.254]/")))

    def test_shared_and_special_use_ipv4_ranges_blocked(self):
        for host in ("100.64.0.1", "192.0.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1"):
            with self.subTest(host=host):
                self.assertTrue(detect_pivoting(call(url=f"http://{host}/")))

    def test_ipv6_multicast_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://[ff02::1]/")))


class TestEvasionResistance(unittest.TestCase):
    def test_percent_encoded_metadata_blocked(self):
        url = "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/"
        self.assertTrue(detect_pivoting(call(url=url)))

    def test_case_insensitive_localhost(self):
        self.assertTrue(detect_pivoting(call(url="http://LOCALHOST/")))

    def test_internal_suffix_blocked(self):
        self.assertTrue(detect_pivoting(call(url="http://db.internal/query")))


class TestBenign(unittest.TestCase):
    def test_public_https_allowed(self):
        self.assertFalse(detect_pivoting(call(url="https://example.com/api")))

    def test_public_api_allowed(self):
        rec = inspect_tool_call(call(url="https://api.github.com/repos"))
        self.assertFalse(rec.blocked)
        self.assertEqual(rec.reason, "external")

    def test_no_url_not_pivoting(self):
        rec = inspect_tool_call(call(tool="calculator"))
        self.assertFalse(rec.blocked)
        self.assertEqual(rec.reason, "no-url")

    def test_nested_arguments_url_inspected(self):
        self.assertTrue(
            detect_pivoting({"tool": "fetch", "arguments": {"url": "http://169.254.169.254/"}})
        )


class TestFailClosed(unittest.TestCase):
    def test_non_mapping_is_pivoting(self):
        self.assertTrue(detect_pivoting("not-a-mapping"))
        self.assertTrue(detect_pivoting(None))

    def test_garbage_url_blocked(self):
        rec = inspect_tool_call(call(url="http://[::1"))
        self.assertTrue(rec.blocked)


class TestRecordShape(unittest.TestCase):
    def test_record_frozen(self):
        rec = check_tool_call("fetch", "https://example.com/")
        with self.assertRaises(Exception):
            rec.blocked = True  # frozen dataclass

    def test_record_as_dict(self):
        rec = check_tool_call("fetch", "http://10.0.0.1/")
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["tool_name"], "fetch")
        self.assertTrue(d["blocked"])

    def test_check_tool_call_convenience(self):
        rec = check_tool_call("webhook", "http://169.254.169.254/")
        self.assertIsInstance(rec, PivotingAttempt)
        self.assertTrue(rec.blocked)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import mcp_pivoting_detector as m
        m.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
