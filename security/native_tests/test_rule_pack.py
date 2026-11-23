"""Structure-only tests for the local rule pack.

These tests read fixture text.  They deliberately do not import, execute, or
subprocess-run any fixture.  Semgrep/OSV behavior is verified separately by the
parent task with the pinned native tools and frozen databases.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules" / "semgrep.yaml"
OSV_CONFIG_PATH = ROOT / "rules" / "osv.toml"
SEVERITY_MAP_PATH = ROOT / "rules" / "severity-map.json"
SEMGREP_ROOT = ROOT / "native_fixtures" / "rule-pack" / "semgrep"
OSV_ROOT = ROOT / "native_fixtures" / "rule-pack" / "osv"

RULE_IDS = {
    "northstar.python.eval-exec": "high",
    "northstar.python.subprocess-shell-true": "high",
    "northstar.python.yaml-unsafe-load": "high",
    "northstar.python.requests-tls-verify-false": "medium",
    "northstar.javascript.child-process-exec": "high",
}

PAIR_EXPECTATIONS = {
    "python_dynamic_execution.py": ("eval(expression)", "parse_fixture_integer"),
    "python_shell_true.py": ("shell=True", "shell=False"),
    "python_yaml_unsafe.py": ("Loader=yaml.Loader", "yaml.safe_load"),
    "python_tls_verify_false.py": ("verify=False", "verify=True"),
    "javascript_child_process_exec.js": ("child_process.exec(command)", "child_process.execFile"),
}


def _read(path: Path) -> str:
    """Read text only; never import or execute fixture code."""
    return path.read_text(encoding="utf-8")


def test_semgrep_rule_document_has_exact_fixed_ids_and_required_fields() -> None:
    document = yaml.safe_load(_read(RULES_PATH))
    assert set(document) == {"rules"}
    rules = document["rules"]
    assert isinstance(rules, list)
    assert [rule["id"] for rule in rules] == list(RULE_IDS)
    assert len({rule["id"] for rule in rules}) == len(RULE_IDS)

    for rule in rules:
        assert set(("id", "languages", "message", "severity", "patterns")) <= set(rule)
        assert rule["severity"] == "ERROR"
        assert rule["languages"] in (["python"], ["javascript"])
        assert isinstance(rule["message"], str) and rule["message"]
        assert isinstance(rule["patterns"], list) and rule["patterns"]


def test_severity_map_is_complete_and_uses_contract_severities() -> None:
    severity_map = json.loads(_read(SEVERITY_MAP_PATH))
    assert severity_map == RULE_IDS
    assert set(severity_map.values()) <= {"critical", "high", "medium", "low", "info", "unknown"}


def test_rules_and_fixtures_contain_no_inline_semgrep_suppression() -> None:
    paths = [RULES_PATH, *SEMGREP_ROOT.rglob("*.*")]
    for path in paths:
        assert "nosem" not in _read(path).lower(), path


@pytest.mark.parametrize("vulnerable_name, fragments", PAIR_EXPECTATIONS.items())
def test_each_programming_risk_has_a_static_vulnerable_and_normal_pair(
    vulnerable_name: str, fragments: tuple[str, str]
) -> None:
    vulnerable = SEMGREP_ROOT / "vulnerable" / vulnerable_name
    normal_name = vulnerable_name.replace("_true.py", "_false.py").replace(
        "_unsafe.py", "_safe.py"
    ).replace("_verify_false.py", "_verify_true.py").replace(
        "_exec.js", "_execfile.js"
    )
    normal = SEMGREP_ROOT / "normal" / normal_name

    assert vulnerable.is_file(), vulnerable
    assert normal.is_file(), normal
    vulnerable_text, normal_text = _read(vulnerable), _read(normal)
    assert fragments[0] in vulnerable_text
    assert fragments[1] in normal_text
    assert "intentionally never invoked" in vulnerable_text
    assert "intentionally never invoked" in normal_text


def test_osv_policy_is_valid_empty_toml_without_suppression_keys() -> None:
    config = tomllib.loads(_read(OSV_CONFIG_PATH))
    assert config == {}
    policy_text = _read(OSV_CONFIG_PATH)
    assert "[[IgnoredVulns]]" not in policy_text
    assert "[[PackageOverrides]]" not in policy_text


def test_osv_fixtures_use_exact_versions_without_options_or_credentials() -> None:
    vulnerable = _read(OSV_ROOT / "vulnerable" / "requirements.txt")
    normal = _read(OSV_ROOT / "normal" / "requirements.txt")
    assert vulnerable == "requests==2.19.1\n"
    assert normal == "wheel==0.46.3\n"
    for text in (vulnerable, normal):
        assert text.count("==") == 1
        assert "--" not in text
        assert "://" not in text
        assert "@" not in text
