"""跨模块互操作测试，不执行真实scanner/build，不保存生产私钥。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "examples"))
from demo_end_to_end import demo
from consume_release import consume_release
from seal_release import seal_release
from sealing_fixtures import build_scenario
from trusted_common import EvidenceError, wire


class EndToEndTests(unittest.TestCase):
    def test_actual_modules_interoperate_with_distinct_start_and_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "demo"
            result = demo(root)
            self.assertTrue(result["source_and_start_commits_differ"])
            self.assertEqual(result["producer_exit_code"], 0)
            self.assertEqual(result["seal_exit_code"], 0)
            self.assertTrue(result["consumer"]["eligible_for_publish"])
            self.assertFalse(list(root.rglob("*.pem")))
            self.assertNotEqual((root / "sealed/producer-gate.json").read_bytes(), (root / "sealed/security-gate.json").read_bytes())

    def test_public_demo_root_stays_external_and_wheel_tamper_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "demo"
            demo(root)
            store = json.loads((root / "demo-trust-store.json").read_bytes())
            identity = json.loads((root / "demo-identity.json").read_bytes())
            sealed = root / "sealed"
            self.assertFalse((sealed / "demo-trust-store.json").exists())
            wheel = next(sealed.glob("*.whl"))
            wheel.chmod(0o600)
            wheel.write_bytes(b"changed fixture bytes")
            self.assertFalse(consume_release(sealed, store, identity)["eligible_for_publish"])

    def test_authentic_expectation_key_cannot_hide_wrong_gate_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            s = build_scenario(root / "scenario")
            gate = json.loads(s.producer_gate_raw)
            gate["host_expectation_sha256"] = "f" * 64
            # 即使错误旧gate重新被受信测试expectation key签名，也必须语义拒绝。
            s.rewrite_expectation_receipt(wire(gate))
            with self.assertRaises(EvidenceError):
                seal_release(s.produced_dir, s.build_capture_path, s.dist_dir, root / "sealed", s.trust, s.identity, s.keys["seal"], now=s.now)
            self.assertFalse((root / "sealed").exists())


if __name__ == "__main__":
    unittest.main()
