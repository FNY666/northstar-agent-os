"""Regression coverage for literal URL SSRF detection (no network access)."""

import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))

import ssrf_detect  # noqa: E402


class SsrfDetectTests(unittest.TestCase):
    def test_private_and_special_use_literals_are_detected(self):
        for url in (
            "http://127.0.0.1/",
            "http://192.168.1.2/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://localhost./",
            "https://api.internal.localhost/",
        ):
            with self.subTest(url=url):
                self.assertTrue(ssrf_detect.is_private_url(url))

    def test_userinfo_cannot_hide_literal_destination(self):
        self.assertTrue(ssrf_detect.is_private_url("http://user:pass@127.0.0.1:8080/"))

    def test_legacy_ipv4_literals_are_normalized_without_dns(self):
        for host in ("127.1", "0177.0.0.1", "0x7f000001", "2130706433"):
            with self.subTest(host=host):
                self.assertTrue(ssrf_detect.is_private_url(f"http://{host}/"))

    def test_unicode_and_encoded_authority_evasions_are_flagged(self):
        for host in ("１２７．０．０．１", "local\u200bhost", "127.0.0.1%2f.evil", "127.0.0.1%5cevil"):
            with self.subTest(host=host):
                self.assertTrue(ssrf_detect.is_private_url(f"http://{host}/"))
        for host in ("169.254.169.254", "0xa9fea9fe", "2852039166"):
            with self.subTest(host=host):
                self.assertTrue(ssrf_detect.is_private_url(f"http://{host}/"))

    def test_public_literals_and_hostnames_are_not_flagged(self):
        for url in (
            "https://1.1.1.1/",
            "https://[2606:4700:4700::1111]/",
            "https://example.com/",
        ):
            with self.subTest(url=url):
                self.assertFalse(ssrf_detect.is_private_url(url))

    def test_only_http_schemes_are_considered(self):
        self.assertFalse(ssrf_detect.is_private_url("file:///etc/passwd"))
        self.assertFalse(ssrf_detect.is_private_url("ftp://127.0.0.1/"))

    def test_malformed_urls_fail_closed_without_raising(self):
        for url in ("http://[::1", "http:///missing-host", "", None):
            with self.subTest(url=url):
                self.assertFalse(ssrf_detect.is_private_url(url))

    def test_module_stays_stdlib_only(self):
        self.assertTrue(ssrf_detect.stdlib_only())


if __name__ == "__main__":
    unittest.main()
