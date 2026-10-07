"""Tests for white_label: tenant branding, themes, domains, assets."""

import ast
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from white_label import (
    ASSET_KINDS,
    STATE_ACTIVE,
    STATE_SUSPENDED,
    TOKEN_NAMES,
    WHITE_LABEL_SCHEMA,
    WHITE_LABEL_VERSION,
    BadAssetError,
    BadThemeError,
    DuplicateDomainError,
    DuplicateTenantError,
    SeqOrderError,
    TenantStateError,
    UnknownAssetError,
    UnknownDomainError,
    UnknownTenantError,
    WhiteLabel,
    WhiteLabelError,
    white_label_audit_event,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "white_label.py")


def make_tenant(wl=None, tid="acme"):
    wl = wl or WhiteLabel()
    return wl, wl.register_tenant(tid, "Acme Corp", 1)


GOOD_TOKENS = {k: "#1a2b3c" for k in TOKEN_NAMES}


# -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert WHITE_LABEL_VERSION == "white-label.v1"
    assert WHITE_LABEL_SCHEMA == "northstar.white-label.v1"


def test_stdlib_only():
    tree = ast.parse(open(MODULE_PATH).read())
    banned = {"requests", "httpx", "urllib", "socket", "aiohttp"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & banned)


def test_main_self_check():
    import subprocess

    out = subprocess.run(
        [sys.executable, MODULE_PATH], capture_output=True, text=True
    )
    assert out.returncode == 0
    assert "white-label OK" in out.stdout


# -- tenants ------------------------------------------------------------


def test_register_roundtrip():
    wl = WhiteLabel()
    rec = wl.register_tenant("acme", "Acme Corp", 1)
    assert rec.tenant_id == "acme"
    assert rec.state == STATE_ACTIVE
    assert rec.theme_digest is None
    assert rec.verify()
    assert wl.tenant_ids() == ("acme",)


def test_register_duplicate():
    wl, _ = make_tenant()
    with pytest.raises(DuplicateTenantError):
        wl.register_tenant("acme", "Acme 2", 2)


def test_register_bad_inputs():
    wl = WhiteLabel()
    with pytest.raises(WhiteLabelError):
        wl.register_tenant("", "x", 1)
    wl2 = WhiteLabel()
    with pytest.raises(WhiteLabelError):
        wl2.register_tenant("t", "", 2)
    wl3 = WhiteLabel()
    with pytest.raises(UnknownTenantError):
        wl3.tenant("nope")


def test_suspend_and_reactivate():
    wl, _ = make_tenant()
    s = wl.suspend_tenant("acme", 2)
    assert s.state == STATE_SUSPENDED and s.verify()
    r = wl.reactivate_tenant("acme", 3)
    assert r.state == STATE_ACTIVE and r.verify()


def test_mutation_while_suspended_refused():
    wl, _ = make_tenant()
    wl.suspend_tenant("acme", 2)
    with pytest.raises(TenantStateError):
        wl.theme("acme", GOOD_TOKENS, 3)
    with pytest.raises(TenantStateError):
        wl.domain("acme", "x.example", 4)
    with pytest.raises(TenantStateError):
        wl.assets("acme", "logo", "sha256:" + "aa" * 32, 5)


# -- themes -------------------------------------------------------------


def test_theme_roundtrip():
    wl, _ = make_tenant()
    rec = wl.theme("acme", GOOD_TOKENS, 2, font_family="Inter", border_radius=12)
    assert rec.verify()
    assert rec.tokens["primary"] == "#1a2b3c"
    assert wl.get_theme("acme").theme_id == rec.theme_id
    # tenant digest pins the theme digest
    assert wl.tenant("acme").theme_digest == rec.digest


def test_theme_bad_color():
    wl, _ = make_tenant()
    bad = dict(GOOD_TOKENS)
    bad["primary"] = "red"
    with pytest.raises(BadThemeError):
        wl.theme("acme", bad, 2)


def test_theme_missing_and_extra_tokens():
    wl, _ = make_tenant()
    short = {k: "#1a2b3c" for k in TOKEN_NAMES[:-1]}
    with pytest.raises(BadThemeError):
        wl.theme("acme", short, 2)
    wl2 = WhiteLabel()
    wl2.register_tenant("acme", "Acme", 1)
    extra = dict(GOOD_TOKENS, neon="x")
    with pytest.raises(BadThemeError):
        wl2.theme("acme", extra, 2)


def test_theme_bad_radius_and_font():
    wl, _ = make_tenant()
    with pytest.raises(BadThemeError):
        wl.theme("acme", GOOD_TOKENS, 2, border_radius=99)
    wl2 = WhiteLabel()
    wl2.register_tenant("acme", "Acme", 1)
    with pytest.raises(BadThemeError):
        wl2.theme("acme", GOOD_TOKENS, 2, font_family="")


# -- domains ------------------------------------------------------------


def test_domain_claim_and_verify():
    wl, _ = make_tenant()
    rec = wl.domain("acme", "App.Acme.Example", 2)
    assert rec.domain == "app.acme.example"  # normalized
    assert rec.verified is False
    assert rec.verification_token
    assert rec.verify()
    vd = wl.verify_domain("acme", "app.acme.example", 3, rec.verification_token)
    assert vd.verified is True
    assert vd.verification_token is None
    assert vd.verify()
    assert wl.domains_for("acme") == (vd,)


def test_domain_duplicate_and_bad():
    wl, _ = make_tenant()
    wl.domain("acme", "app.acme.example", 2)
    with pytest.raises(DuplicateDomainError):
        wl.domain("acme", "APP.ACME.EXAMPLE", 3)
    wl3 = WhiteLabel()
    wl3.register_tenant("b", "B", 1)
    with pytest.raises(WhiteLabelError):
        wl3.domain("b", "not a domain!!", 2)


def test_domain_token_mismatch():
    wl, _ = make_tenant()
    wl.domain("acme", "app.acme.example", 2)
    with pytest.raises(WhiteLabelError):
        wl.verify_domain("acme", "app.acme.example", 3, "wrong-token")


def test_domain_verify_unknown():
    wl, _ = make_tenant()
    with pytest.raises(UnknownDomainError):
        wl.verify_domain("acme", "nope.example", 2, "x")


def test_domain_release():
    wl, _ = make_tenant()
    rec = wl.domain("acme", "app.acme.example", 2)
    released = wl.release_domain("acme", "app.acme.example", 3)
    assert released.domain == rec.domain
    assert wl.domains_for("acme") == ()
    # now another tenant may claim it
    wl2 = WhiteLabel()
    wl2.register_tenant("beta", "Beta", 1)
    wl2.domain("beta", "app.acme.example", 2)  # no error


# -- assets -------------------------------------------------------------


def test_assets_roundtrip():
    wl, _ = make_tenant()
    digest = "sha256:" + "ab" * 32
    rec = wl.assets("acme", "logo", digest, 2, label="primary")
    assert rec.verify()
    assert rec.content_digest == digest
    assert wl.get_asset("acme", "logo").asset_id == rec.asset_id
    # replace with a newer pin
    rec2 = wl.assets("acme", "logo", "sha256:" + "cd" * 32, 3)
    assert rec2.asset_id != rec.asset_id
    assert wl.get_asset("acme", "logo").asset_id == rec2.asset_id


def test_assets_bad_kind_and_digest():
    wl, _ = make_tenant()
    with pytest.raises(BadAssetError):
        wl.assets("acme", "watermark", "sha256:" + "ab" * 32, 2)
    with pytest.raises(BadAssetError):
        wl.assets("acme", "logo", "not-a-digest", 3)


def test_assets_unknown_lookup_and_unpin():
    wl, _ = make_tenant()
    with pytest.raises(UnknownAssetError):
        wl.get_asset("acme", "favicon")
    rec = wl.assets("acme", "favicon", "sha256:" + "ab" * 32, 2)
    out = wl.unpin_asset("acme", "favicon", 3)
    assert out.asset_id == rec.asset_id
    with pytest.raises(UnknownAssetError):
        wl.get_asset("acme", "favicon")
    wl2 = WhiteLabel()
    wl2.register_tenant("b", "B", 1)
    with pytest.raises(UnknownAssetError):
        wl2.unpin_asset("b", "logo", 2)


# -- seq discipline -----------------------------------------------------


def test_seq_order_enforced():
    wl, _ = make_tenant()
    wl.theme("acme", GOOD_TOKENS, 2)
    with pytest.raises(SeqOrderError):
        wl.theme("acme", GOOD_TOKENS, 2)  # rewind
    with pytest.raises(SeqOrderError):
        wl.domain("acme", "a.example", True)  # bool seq
    with pytest.raises(SeqOrderError):
        wl.assets("acme", "logo", "sha256:" + "ab" * 32, -1)


def test_failed_mutation_consumes_seq():
    wl, _ = make_tenant()
    with pytest.raises(BadThemeError):
        wl.theme("acme", {}, 2)
    # seq 2 was consumed by the failed mutation
    with pytest.raises(SeqOrderError):
        wl.theme("acme", GOOD_TOKENS, 2)
    rec = wl.theme("acme", GOOD_TOKENS, 3)
    assert rec.verify()


# -- audit --------------------------------------------------------------


def test_audit_shapes_and_no_value_leak():
    wl, _ = make_tenant()
    wl.theme("acme", GOOD_TOKENS, 2)
    d = wl.domain("acme", "app.acme.example", 3)
    wl.verify_domain("acme", "app.acme.example", 4, d.verification_token or "")
    wl.assets("acme", "logo", "sha256:" + "ab" * 32, 5)
    log = wl.audit_log()
    kinds = [e["kind"] for e in log]
    assert "theme-set" in kinds and "domain-verified" in kinds
    assert all(e["schema"] == "audit.ndjson/1" for e in log)
    # audit events carry ids + digests, never asset labels or tokens
    blob = str(log)
    assert "#1a2b3c" not in blob


def test_audit_event_helper():
    ev = white_label_audit_event("tenant-registered", 1, tenant_id="acme")
    assert ev["kind"] == "tenant-registered"
    assert ev["module_version"] == WHITE_LABEL_VERSION
    with pytest.raises(WhiteLabelError):
        white_label_audit_event("bogus-kind", 1)


def test_as_dict_and_views():
    wl, _ = make_tenant()
    wl.theme("acme", GOOD_TOKENS, 2)
    wl.domain("acme", "app.acme.example", 3)
    snap = wl.as_dict()
    assert snap["tenants"] == 1 and snap["domains"] == 1
    assert snap["schema"] == WHITE_LABEL_SCHEMA
