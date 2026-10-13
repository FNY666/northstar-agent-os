"""Tests for the seal-merkle-batch checkpoint module, Simulated."""

import ast
import dataclasses
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "seal_merkle_batch.py"


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("seal_merkle_batch", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["seal_merkle_batch"] = module
    spec.loader.exec_module(module)
    return module


smb = _load()


def PIN(i):
    return "sha256:" + f"{i:064x}"


# 1. version/schema pins
def test_version_and_schema_pins():
    assert smb.SEAL_MERKLE_BATCH_VERSION == "seal-merkle-batch.v1"
    assert smb.SCHEMA_PIN == "northstar.seal-merkle-batch.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    assert smb.stdlib_only() is True
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "pathlib",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. seal_batch roundtrip: 5 pins
def test_seal_batch_roundtrip():
    pins = [PIN(i) for i in range(1, 6)]
    batch = smb.seal_batch(pins, first_seq=7)
    assert batch.root.startswith("sha256:")
    assert len(batch.root) == 71
    assert batch.depth == 3
    assert batch.first_seq == 7
    assert batch.record_hashes == tuple(pins)
    assert isinstance(batch.record_hashes, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        batch.depth = 99  # type: ignore[misc]


# 4. bad-input table
def test_seal_batch_bad_inputs():
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch([])
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch(["not-a-pin"])
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch(["sha256:" + "zz" * 32])  # malformed hex
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch([PIN(1)], first_seq=0)
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch([PIN(1)], first_seq=True)
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch([123])  # non-str leaf
    with pytest.raises(smb.MerkleBatchError):
        smb.seal_batch([PIN(1)], first_seq="1")


# 5. proof() for each index in a 5-leaf batch
def test_proof_all_indices_verify():
    pins = [PIN(i) for i in range(1, 6)]
    batch = smb.seal_batch(pins)
    for i, pin in enumerate(pins):
        proof = batch.proof(i)
        assert proof.leaf_index == i
        assert proof.leaf_hash == pin
        assert proof.root == batch.root
        assert len(proof.siblings) == len(proof.sibling_is_left)
        assert smb.verify_proof(pin, proof, batch.root) is True


# 6. proof out-of-range
def test_proof_out_of_range():
    batch = smb.seal_batch([PIN(i) for i in range(1, 6)])
    with pytest.raises(smb.MerkleBatchError):
        batch.proof(-1)
    with pytest.raises(smb.MerkleBatchError):
        batch.proof(5)
    with pytest.raises(smb.MerkleBatchError):
        batch.proof(True)
    with pytest.raises(smb.MerkleBatchError):
        batch.proof("0")


# 7. tamper: wrong leaf / wrong root / foreign proof
def test_verify_tamper():
    pins = [PIN(i) for i in range(1, 6)]
    batch = smb.seal_batch(pins)
    proof0 = batch.proof(0)
    assert smb.verify_proof(PIN(2), proof0, batch.root) is False
    assert smb.verify_proof(PIN(1), proof0, PIN(99)) is False
    other = smb.seal_batch([PIN(i) for i in range(10, 15)])
    assert smb.verify_proof(PIN(1), proof0, other.root) is False
    # proof from a different batch against this root
    foreign_proof = other.proof(0)
    assert smb.verify_proof(PIN(10), foreign_proof, batch.root) is False


# 8. corrupted proof data -> False (never raises)
def test_verify_corrupted_proof():
    pins = [PIN(i) for i in range(1, 6)]
    batch = smb.seal_batch(pins)
    proof = batch.proof(2)
    # flip a hex digit in the first sibling
    sibs = list(proof.siblings)
    flipped = ("0" if sibs[0][0] != "0" else "1") + sibs[0][1:]
    bad = dataclasses.replace(proof, siblings=tuple([flipped] + sibs[1:]))
    assert smb.verify_proof(PIN(3), bad, batch.root) is False
    # truncated sibling
    bad2 = dataclasses.replace(proof, siblings=tuple([sibs[0][:10]] + sibs[1:]))
    assert smb.verify_proof(PIN(3), bad2, batch.root) is False
    # non-hex sibling
    bad3 = dataclasses.replace(proof, siblings=tuple(["zz" * 32] + sibs[1:]))
    assert smb.verify_proof(PIN(3), bad3, batch.root) is False
    # mismatched siblings / is_left lengths
    bad4 = dataclasses.replace(proof, sibling_is_left=proof.sibling_is_left + (True,))
    assert smb.verify_proof(PIN(3), bad4, batch.root) is False


# 9. single-leaf batch
def test_single_leaf_batch():
    batch = smb.seal_batch([PIN(1)])
    assert batch.depth == 0
    proof = batch.proof(0)
    assert proof.siblings == ()
    assert smb.verify_proof(PIN(1), proof, batch.root) is True


# 10. power-of-2 batch (8 leaves)
def test_power_of_two_batch():
    pins = [PIN(i) for i in range(1, 9)]
    batch = smb.seal_batch(pins)
    assert batch.depth == 3
    for i, pin in enumerate(pins):
        assert smb.verify_proof(pin, batch.proof(i), batch.root) is True


# 11. determinism
def test_determinism():
    pins = [PIN(i) for i in range(1, 6)]
    a = smb.seal_batch(pins)
    b = smb.seal_batch(list(pins))
    assert a.root == b.root
    rev = smb.seal_batch(list(reversed(pins)))
    assert rev.root != a.root


# 12. odd-leaf duplication: 3-leaf root matches manual construction
def test_odd_leaf_duplication():
    pins = [PIN(1), PIN(2), PIN(3)]

    def leaf(pin):
        return hashlib.sha256(b"\x00" + bytes.fromhex(pin[7:])).digest()

    def node(left, right):
        return hashlib.sha256(b"\x01" + left + right).digest()

    h = [leaf(p) for p in pins]
    # level 1: [h0, h1, h2, h2] (last duplicated)
    n01 = node(h[0], h[1])
    n22 = node(h[2], h[2])
    expected = "sha256:" + node(n01, n22).hex()
    batch = smb.seal_batch(pins)
    assert batch.root == expected
    assert batch.depth == 2


# 13. domain separation: leaf hash != node hash for same preimage
def test_domain_separation():
    pin = PIN(42)
    single = smb.seal_batch([pin])
    double = smb.seal_batch([pin, pin])
    # single-leaf root = SHA256(0x00 || raw); two-leaf root = SHA256(0x01 || h || h)
    assert single.root != double.root
    # direct check of the domain tags on identical preimages
    raw = bytes.fromhex(pin[7:])
    leaf_digest = hashlib.sha256(b"\x00" + raw).digest()
    node_digest = hashlib.sha256(b"\x01" + raw + raw).digest()
    assert leaf_digest != node_digest


# 14. verify_proof argument validation
def test_verify_proof_argument_validation():
    batch = smb.seal_batch([PIN(1), PIN(2)])
    proof = batch.proof(0)
    with pytest.raises(smb.MerkleBatchError):
        smb.verify_proof(PIN(1), "not-a-proof", batch.root)  # type: ignore[arg-type]
    with pytest.raises(smb.MerkleBatchError):
        smb.verify_proof("nope", proof, batch.root)
    with pytest.raises(smb.MerkleBatchError):
        smb.verify_proof(PIN(1), proof, "nope")
    with pytest.raises(smb.MerkleBatchError):
        smb.verify_proof(123, proof, batch.root)  # type: ignore[arg-type]


# 15. main() subprocess check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout
