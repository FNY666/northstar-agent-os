"""PII vault tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pv = _load("pii_vault")


def test_mask_email():
    v = pv.Vault()
    masked, tokens = v.mask("Email me at a@b.com", "r1")
    assert "a@b.com" not in masked
    assert "[EMAIL_0]" in masked


def test_mask_phone():
    v = pv.Vault()
    masked, _ = v.mask("Call 555-123-4567", "r1")
    assert "555-123-4567" not in masked


def test_demask():
    v = pv.Vault()
    masked, _ = v.mask("Email a@b.com", "r1")
    restored = v.demask(masked, "r1")
    assert "a@b.com" in restored


def test_scoped_demask():
    v = pv.Vault()
    masked, _ = v.mask("Email a@b.com phone 555-123-4567", "r1")
    partial = v.demask(masked, "r1", allowed_types=["EMAIL"])
    assert "a@b.com" in partial
    assert "[PHONE_0]" in partial


def test_clear():
    v = pv.Vault()
    masked, _ = v.mask("a@b.com", "r1")
    v.clear_run("r1")
    # After clear, demask does nothing.
    assert v.demask(masked, "r1") == masked


def test_isolated_runs():
    v = pv.Vault()
    m1, _ = v.mask("a@b.com", "run1")
    m2, _ = v.mask("a@b.com", "run2")
    # Different runs, different vaults (but same token names).
    # Demask run1 doesn't affect run2.
    assert v.demask(m1, "run1") == "a@b.com"
    assert v.demask(m2, "run2") == "a@b.com"


def test_stdlib_only():
    assert pv.stdlib_only() is True


def test_version_pin():
    assert pv.PII_VAULT_VERSION == "pii-vault.v1"
