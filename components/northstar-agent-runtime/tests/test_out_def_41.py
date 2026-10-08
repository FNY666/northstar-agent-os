"""PDF metadata scrubber tests."""

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


m41 = _load("out_def_41")


def test_pdf_metadata_removed():
    pdf = (
        b"%PDF-1.4\n1 0 obj\n<< /Author (John Doe) /Creator (Acme)"
        b" /Producer (AcmePDF) /CreationDate (D:20260101) /ModDate (D:20260102)"
        b" /Title <FEFF00480069> /Subject (Test) /Keywords (a,b) /Pages 2 0 R >>\n"
    )
    cleaned, removed = m41.clean_pdf_metadata(pdf)
    assert set(removed) == {
        "Author", "Creator", "Producer", "CreationDate",
        "ModDate", "Title", "Subject", "Keywords",
    }
    assert b"John Doe" not in cleaned
    assert b"AcmePDF" not in cleaned
    assert b"FEFF00480069" not in cleaned
    assert b"/Pages" in cleaned


def test_escaped_parens_handled():
    pdf = b"<< /Author (Acme \\(Ltd\\)) /Pages 1 0 R >>"
    cleaned, removed = m41.clean_pdf_metadata(pdf)
    assert removed == ["Author"]
    assert b"Acme" not in cleaned
    assert b"/Pages" in cleaned


def test_clean_input_unchanged():
    clean = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    out, removed = m41.clean_pdf_metadata(clean)
    assert out == clean
    assert removed == []


def test_malformed_does_not_raise():
    for bad in (b"", b"/Author (unclosed", b"\xff\xfe\x00\x01", b"/Title <ZZZ>"):
        out, removed = m41.clean_pdf_metadata(bad)
        assert isinstance(out, bytes)
        assert isinstance(removed, list)


def test_stdlib_only():
    assert m41.stdlib_only() is True


def test_version_pin():
    assert m41.OUT_DEF_41_VERSION == "out-def-41.v1"
    assert m41.SCHEMA_PIN == "northstar.out-def-41.v1"
