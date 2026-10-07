"""Tests for sdk_generation."""

import ast
import subprocess
import sys

import pytest

from sdk_generation import (
    SDKGeneration,
    SDKGenerationError,
    BadVersionError,
    BadBuildError,
    BadPublishError,
    AlreadyPublishedError,
    NotPublishedError,
    DuplicateSpecError,
    UnknownSpecError,
    UnknownBuildError,
    SeqOrderError,
    SDK_GENERATION_VERSION,
    SDK_GENERATION_SCHEMA,
    LANGUAGES,
    REGISTRIES,
    BUMPS,
    sdk_generation_audit_event,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def fresh():
    return SDKGeneration()


# ---------------------------------------------------------------------------
# Pins and stdlib-only
# ---------------------------------------------------------------------------


def test_pins():
    assert SDK_GENERATION_VERSION == "sdk-generation.v1"
    assert SDK_GENERATION_SCHEMA == "northstar.sdk-generation.v1"
    assert "python" in LANGUAGES and "go" in LANGUAGES
    assert "pypi" in REGISTRIES and "npm" in REGISTRIES
    assert BUMPS == frozenset({"major", "minor", "patch"})


def test_stdlib_only():
    import pathlib

    tree = ast.parse(pathlib.Path("sdk_generation.py").read_text())
    allowed = {
        "hashlib",
        "json",
        "re",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# Spec registration
# ---------------------------------------------------------------------------


def test_register_spec_roundtrip():
    gen = fresh()
    rec = gen.register_spec("petstore", GOOD_DIGEST, 24, seq=1)
    assert rec.verify()
    assert gen.spec_record("petstore") == rec
    assert rec.operation_count == 24


def test_register_spec_duplicate_refused():
    gen = fresh()
    gen.register_spec("petstore", GOOD_DIGEST, 24, seq=1)
    with pytest.raises(DuplicateSpecError):
        gen.register_spec("petstore", GOOD_DIGEST, 24, seq=2)


def test_register_spec_bad_inputs():
    gen = fresh()
    with pytest.raises(SDKGenerationError):
        gen.register_spec("bad id!", GOOD_DIGEST, 1, seq=1)
    with pytest.raises(SDKGenerationError):
        gen.register_spec("s2", "not-a-digest", 1, seq=2)
    with pytest.raises(SDKGenerationError):
        gen.register_spec("s3", GOOD_DIGEST, -1, seq=3)


# ---------------------------------------------------------------------------
# Generate / publish / withdraw / version
# ---------------------------------------------------------------------------


def _gen_with_spec(gen, seq=1):
    gen.register_spec("petstore", GOOD_DIGEST, 24, seq=seq)
    return gen.generate("petstore", "python", "petstore-sdk", "1.2.3", seq=seq + 1)


def test_generate_roundtrip():
    gen = fresh()
    build = _gen_with_spec(gen)
    assert build.verify()
    assert build.language == "python"
    assert build.sdk_version == "1.2.3"
    assert build.prev_build_id == ""
    assert "petstore-sdk 1.2.3 (python)" in build.bundle_text
    assert gen.build_record(build.build_id) == build
    assert gen.builds_for_spec("petstore") == [build]


def test_generate_bad_language_and_version():
    gen = fresh()
    gen.register_spec("petstore", GOOD_DIGEST, 24, seq=1)
    with pytest.raises(BadBuildError):
        gen.generate("petstore", "cobol", "x", "1.0.0", seq=2)
    with pytest.raises(BadVersionError):
        gen.generate("petstore", "python", "x", "1.0", seq=3)
    with pytest.raises(UnknownSpecError):
        gen.generate("ghost", "python", "x", "1.0.0", seq=4)


def test_publish_withdraw_cycle():
    gen = fresh()
    build = _gen_with_spec(gen)
    pub = gen.publish(build.build_id, "pypi", seq=3)
    assert pub.verify() and pub.active
    assert gen.active_publication(build.build_id, "pypi") == pub
    with pytest.raises(AlreadyPublishedError):
        gen.publish(build.build_id, "pypi", seq=4)
    wd = gen.withdraw(pub.publish_id, seq=5, reason="yank")
    assert wd.verify()
    assert gen.active_publication(build.build_id, "pypi") is None
    with pytest.raises(NotPublishedError):
        gen.withdraw(pub.publish_id, seq=6)


def test_version_bumps():
    gen = fresh()
    build = _gen_with_spec(gen)
    patch = gen.version(build.build_id, "patch", seq=3)
    assert patch.sdk_version == "1.2.4"
    assert patch.prev_build_id == build.build_id
    assert patch.verify()
    minor = gen.version(build.build_id, "minor", seq=4)
    assert minor.sdk_version == "1.3.0"
    major = gen.version(build.build_id, "major", seq=5)
    assert major.sdk_version == "2.0.0"
    with pytest.raises(BadVersionError):
        gen.version(build.build_id, "mega", seq=6)
    with pytest.raises(UnknownBuildError):
        gen.version("sdk-999", "patch", seq=7)


# ---------------------------------------------------------------------------
# Seq discipline and audit boundary
# ---------------------------------------------------------------------------


def test_seq_ordering_and_burn():
    gen = fresh()
    gen.register_spec("s1", GOOD_DIGEST, 1, seq=1)
    with pytest.raises(SeqOrderError):
        gen.register_spec("s2", GOOD_DIGEST, 1, seq=1)  # rewind
    with pytest.raises(SeqOrderError):
        gen.register_spec("s3", GOOD_DIGEST, 1, seq=True)  # bool
    # failed mutation consumed seq=1.. wait: seq=1 consumed; rewind refused
    # before consuming. A failing mutation consumes: duplicate at fresh seq.
    gen.register_spec("dup", GOOD_DIGEST, 1, seq=2)
    with pytest.raises(DuplicateSpecError):
        gen.register_spec("dup", GOOD_DIGEST, 1, seq=3)
    with pytest.raises(SeqOrderError):  # seq 3 was consumed by the failure
        gen.register_spec("ok", GOOD_DIGEST, 1, seq=3)
    rec = gen.register_spec("ok", GOOD_DIGEST, 1, seq=4)
    assert rec.verify()


def test_audit_shapes_and_banned_keys():
    gen = fresh()
    gen.register_spec("s1", GOOD_DIGEST, 2, seq=1)
    build = gen.generate("s1", "go", "my-sdk", "0.1.0", seq=2)
    gen.publish(build.build_id, "crates", seq=3)
    log = gen.audit_log()
    kinds = [row["kind"] for row in log]
    assert kinds == ["spec-registered", "sdk-generated", "sdk-published"]
    assert all(row["schema"] == "audit.ndjson/1" for row in log)
    with pytest.raises(SDKGenerationError):
        sdk_generation_audit_event("bogus", {}, seq=4)
    with pytest.raises(SDKGenerationError):
        sdk_generation_audit_event(
            "sdk-generated", {"bundle_text": "x"}, seq=5
        )


# ---------------------------------------------------------------------------
# Cross-instance determinism and main()
# ---------------------------------------------------------------------------


def test_cross_instance_determinism():
    a, b = fresh(), fresh()
    a.register_spec("s", GOOD_DIGEST, 3, seq=1)
    b.register_spec("s", GOOD_DIGEST, 3, seq=1)
    ba = a.generate("s", "rust", "sdk", "2.0.0", seq=2)
    bb = b.generate("s", "rust", "sdk", "2.0.0", seq=2)
    assert ba.digest == bb.digest
    assert ba.bundle_text == bb.bundle_text


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "sdk_generation.py"],
        capture_output=True,
        text=True,
        cwd=".",
    )
    assert proc.returncode == 0, proc.stderr
    assert "sdk-generation OK" in proc.stdout


def test_py_compile():
    import py_compile

    py_compile.compile("sdk_generation.py", doraise=True)


def test_withdraw_bad_inputs():
    gen = fresh()
    build = _gen_with_spec(gen)
    pub = gen.publish(build.build_id, "npm", seq=3)
    with pytest.raises(UnknownBuildError):
        gen.withdraw("pub-999", seq=4)
    with pytest.raises(BadPublishError):
        gen.publish(build.build_id, "not-a-registry", seq=5)
    with pytest.raises(BadPublishError):
        gen.withdraw(pub.publish_id, seq=6, reason="x" * 257)
