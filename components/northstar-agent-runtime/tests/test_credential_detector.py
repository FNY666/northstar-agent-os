"""Tests for credential_detector (15 tests)."""
from __future__ import annotations

import unittest

from credential_detector import (
    CREDENTIAL_DETECTOR_VERSION,
    CredentialFinding,
    CredentialType,
    mask_value,
    scan_for_credentials,
)


class TestMaskValue(unittest.TestCase):
    def test_long_value(self) -> None:
        self.assertEqual(mask_value("abcdefghij"), "ab******ij")

    def test_short_value(self) -> None:
        self.assertEqual(mask_value("abcd"), "****")

    def test_non_str_raises(self) -> None:
        with self.assertRaises(TypeError):
            mask_value(123)  # type: ignore[arg-type]


class TestScanForCredentials(unittest.TestCase):
    def test_openai_api_key(self) -> None:
        findings = scan_for_credentials('api_key: "sk-abc123DEF456ghi789JKL"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].credential_type, CredentialType.API_KEY)
        self.assertEqual(findings[0].line_number, 1)

    def test_aws_access_key(self) -> None:
        findings = scan_for_credentials("key = AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(any(f.credential_type is CredentialType.API_KEY for f in findings))

    def test_github_token(self) -> None:
        findings = scan_for_credentials('token = "ghp_abcdefghij1234567890"')
        self.assertTrue(any(f.credential_type is CredentialType.API_KEY for f in findings))

    def test_password_assignment(self) -> None:
        findings = scan_for_credentials("db_password = hunter2")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].credential_type, CredentialType.PASSWORD)

    def test_bearer_token(self) -> None:
        findings = scan_for_credentials("auth: Bearer aBcDeFgH1234567890")
        self.assertTrue(any(f.credential_type is CredentialType.TOKEN for f in findings))

    def test_jwt_shape(self) -> None:
        findings = scan_for_credentials(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        self.assertTrue(any(f.credential_type is CredentialType.TOKEN for f in findings))

    def test_private_key_block(self) -> None:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBOgIBAAJBAKqX2g==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        findings = scan_for_credentials(pem)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].credential_type, CredentialType.PRIVATE_KEY)

    def test_env_var_reference_not_flagged(self) -> None:
        findings = scan_for_credentials("api_key: ${API_KEY}\ntoken: ${TOKEN}")
        self.assertEqual(findings, [])

    def test_clean_text(self) -> None:
        findings = scan_for_credentials("just a normal config line\nanother one")
        self.assertEqual(findings, [])

    def test_line_numbers(self) -> None:
        findings = scan_for_credentials("clean\npassword = hunter2\nclean")
        self.assertEqual(findings[0].line_number, 2)

    def test_raw_secret_not_in_finding(self) -> None:
        secret = "sk-abc123DEF456ghi789JKL"
        findings = scan_for_credentials(f'key: "{secret}"')
        self.assertNotIn(secret, findings[0].masked_value)

    def test_non_str_raises(self) -> None:
        with self.assertRaises(TypeError):
            scan_for_credentials(None)  # type: ignore[arg-type]

    def test_version_pin(self) -> None:
        self.assertEqual(CREDENTIAL_DETECTOR_VERSION, "credential-detector.v1")

    def test_finding_validation(self) -> None:
        with self.assertRaises(ValueError):
            CredentialFinding(CredentialType.API_KEY, "ab", 0)


if __name__ == "__main__":
    unittest.main()
