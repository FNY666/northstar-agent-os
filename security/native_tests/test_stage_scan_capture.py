import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from producer_fixtures import build_scenario
from stage_scan_capture import stage_scan_capture
from trusted_common import EvidenceError,sha


class StageCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.s=build_scenario(self.root/'scenario')
        self.capture=self.root/'capture'
        self.capture.mkdir()
        for item in self.s.evidence_dir.iterdir():
            (self.capture/item.name).write_bytes(item.read_bytes())
        (self.capture/'capture.dsse.json').write_bytes(self.s.capture_path.read_bytes())

    def tearDown(self):self.temp.cleanup()

    def stage(self):
        return stage_scan_capture(self.capture,self.root/'staged',self.s.trust,self.s.identity,sha(self.s.plan_path.read_bytes()))

    def test_verified_capture_stages_only_authenticated_evidence(self):
        result=self.stage()
        self.assertEqual(result['exit_code'],0)
        self.assertFalse((self.root/'staged/capture.dsse.json').exists())
        self.assertEqual({p.name for p in (self.root/'staged').iterdir()},{p.name for p in self.s.evidence_dir.iterdir()})

    def test_extra_file_or_substituted_stdout_rejected(self):
        (self.capture/'extra').write_bytes(b'toy')
        with self.assertRaises(EvidenceError):self.stage()
        (self.capture/'extra').unlink()
        stdout=next(self.capture.glob('*.stdout.json'))
        stdout.write_bytes(b'{}')
        with self.assertRaises(EvidenceError):self.stage()
        self.assertFalse((self.root/'staged').exists())

    def test_capture_must_pin_independently_verified_plan(self):
        with self.assertRaises(EvidenceError):
            stage_scan_capture(self.capture,self.root/'staged',self.s.trust,self.s.identity,'f'*64)

    def test_capture_signature_and_external_nonce_not_self_approved(self):
        current=dict(self.s.identity,nonce='c'*64)
        with self.assertRaises(EvidenceError):
            stage_scan_capture(self.capture,self.root/'staged',self.s.trust,current,sha(self.s.plan_path.read_bytes()))

    def test_copackaged_symlink_is_not_accepted_as_same_signature(self):
        path=self.capture/'capture.dsse.json'
        path.unlink()
        path.symlink_to(self.s.capture_path)
        with self.assertRaises((EvidenceError,OSError)):self.stage()


if __name__=='__main__':unittest.main()
