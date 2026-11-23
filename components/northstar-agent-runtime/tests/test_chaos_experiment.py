"""Tests for chaos_experiment: fault-injection bookkeeping."""

import threading
import unittest

from chaos_experiment import (
    AbortRecord,
    BlastRadius,
    ChaosError,
    ChaosExperiment,
    DuplicateExperimentError,
    ExperimentDefinition,
    ExperimentStateError,
    ExperimentStatus,
    ExperimentValidationError,
    FaultAssignment,
    FaultSpec,
    RunReport,
    UnknownExperimentError,
    VERSION,
    SCHEMA,
    AUDIT_FORMAT,
    FAULT_TYPES,
    MAX_BLAST_RADIUS_PCT,
    chaos_experiment_audit_event,
)

MODULE = "chaos_experiment"


def _exp():
    return ChaosExperiment()


def _define(exp, exp_id="e1", targets=("t0", "t1", "t2", "t3"),
            pct=25, faults=None, seq=1):
    if faults is None:
        faults = (FaultSpec("pod-kill", (("duration_seqs", 5),)),)
    return exp.define(exp_id, faults, targets, BlastRadius(pct), seq)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(VERSION, "chaos-experiment.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA, "northstar.chaos-experiment.v1")

    def test_audit_format(self):
        self.assertEqual(AUDIT_FORMAT, "audit.ndjson/1")

    def test_fault_vocab_nonempty(self):
        self.assertIn("pod-kill", FAULT_TYPES)
        self.assertIn("network-partition", FAULT_TYPES)
        self.assertIn("stress-cpu", FAULT_TYPES)
        self.assertEqual(MAX_BLAST_RADIUS_PCT, 50)


class TestFaultSpec(unittest.TestCase):
    def test_valid_fault(self):
        f = FaultSpec("network-delay", (("delay_ms", 200),))
        self.assertTrue(f.digest.startswith("sha256:"))
        self.assertEqual(f.fault_type, "network-delay")

    def test_unknown_fault_type_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            FaultSpec("nuke-everything")

    def test_nan_param_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            FaultSpec("stress-cpu", (("load", float("nan")),))

    def test_huge_int_param_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            FaultSpec("disk-fill", (("bytes", 2 ** 54),))

    def test_digest_determinism(self):
        a = FaultSpec("pod-kill", (("duration_seqs", 10),))
        b = FaultSpec("pod-kill", (("duration_seqs", 10),))
        self.assertEqual(a.digest, b.digest)

    def test_as_dict(self):
        f = FaultSpec("pod-kill", (("duration_seqs", 10),))
        d = f.as_dict()
        self.assertEqual(d["fault_type"], "pod-kill")
        self.assertEqual(d["params"]["duration_seqs"], 10)


class TestBlastRadius(unittest.TestCase):
    def test_budget_pct(self):
        r = BlastRadius(25)
        self.assertEqual(r.budget(4), 1)
        self.assertEqual(r.budget(8), 2)

    def test_budget_count_cap(self):
        r = BlastRadius(50, max_affected_count=1)
        self.assertEqual(r.budget(10), 1)

    def test_pct_over_cap_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            BlastRadius(51)

    def test_zero_pct_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            BlastRadius(0)

    def test_bad_count_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            BlastRadius(25, max_affected_count=0)

    def test_pct_floor_is_one(self):
        # 1% of 10 targets still books exactly one target.
        r = BlastRadius(1)
        self.assertEqual(r.budget(10), 1)


class TestDefine(unittest.TestCase):
    def test_define_happy_path(self):
        exp = _exp()
        d = _define(exp)
        self.assertIsInstance(d, ExperimentDefinition)
        self.assertTrue(d.digest.startswith("sha256:"))
        self.assertEqual(d.budget, 1)
        self.assertEqual(exp.status("e1").state, "defined")

    def test_duplicate_id_rejected(self):
        exp = _exp()
        _define(exp)
        with self.assertRaises(DuplicateExperimentError):
            _define(exp, seq=2)

    def test_empty_faults_rejected(self):
        exp = _exp()
        with self.assertRaises(ExperimentValidationError):
            _define(exp, faults=(), seq=1)

    def test_empty_targets_rejected(self):
        exp = _exp()
        with self.assertRaises(ExperimentValidationError):
            _define(exp, targets=(), seq=1)

    def test_duplicate_targets_rejected(self):
        exp = _exp()
        with self.assertRaises(ExperimentValidationError):
            _define(exp, targets=("a", "a"), seq=1)

    def test_non_faultspec_rejected(self):
        exp = _exp()
        with self.assertRaises(ExperimentValidationError):
            _define(exp, faults=("pod-kill",), seq=1)

    def test_seq_must_advance(self):
        exp = _exp()
        _define(exp, seq=5)
        with self.assertRaises(ExperimentValidationError):
            _define(exp, exp_id="e2", seq=5)

    def test_definition_view(self):
        exp = _exp()
        d = _define(exp)
        self.assertEqual(exp.definition("e1"), d)

    def test_unknown_definition(self):
        exp = _exp()
        with self.assertRaises(UnknownExperimentError):
            exp.definition("nope")


class TestRun(unittest.TestCase):
    def test_run_assignments_within_budget(self):
        exp = _exp()
        _define(exp, targets=tuple(f"web-{i}" for i in range(8)), pct=25)
        report = exp.run("e1", seq=2)
        self.assertIsInstance(report, RunReport)
        self.assertEqual(len(report.assignments), 2)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_run_deterministic(self):
        a, b = _exp(), _exp()
        _define(a, targets=("t0", "t1", "t2", "t3"))
        _define(b, targets=("t0", "t1", "t2", "t3"))
        ra, rb = a.run("e1", seq=2), b.run("e1", seq=2)
        self.assertEqual(ra.affected_targets, rb.affected_targets)
        self.assertEqual(ra.digest, rb.digest)

    def test_faults_round_robin(self):
        exp = _exp()
        faults = (
            FaultSpec("pod-kill", (("duration_seqs", 1),)),
            FaultSpec("network-loss", (("loss_pct", 10),)),
        )
        _define(exp, faults=faults, targets=("a", "b"), pct=50)
        report = exp.run("e1", seq=2)
        self.assertEqual(len(report.assignments), 1)
        used = {a.fault.fault_type for a in report.assignments}
        self.assertTrue(used <= {"pod-kill", "network-loss"})

    def test_run_unknown_rejected(self):
        exp = _exp()
        with self.assertRaises(UnknownExperimentError):
            exp.run("nope", seq=1)

    def test_run_twice_rejected(self):
        exp = _exp()
        _define(exp)
        exp.run("e1", seq=2)
        with self.assertRaises(ExperimentStateError):
            exp.run("e1", seq=3)

    def test_assignment_digest_pins(self):
        exp = _exp()
        _define(exp, targets=("a", "b"))
        report = exp.run("e1", seq=2)
        for a in report.assignments:
            self.assertIsInstance(a, FaultAssignment)
            self.assertTrue(a.digest.startswith("sha256:"))


class TestAbortAndComplete(unittest.TestCase):
    def test_abort_happy_path(self):
        exp = _exp()
        _define(exp)
        exp.run("e1", seq=2)
        record = exp.abort("e1", seq=3)
        self.assertIsInstance(record, AbortRecord)
        self.assertTrue(record.digest.startswith("sha256:"))
        st = exp.status("e1")
        self.assertEqual(st.state, "aborted")
        self.assertEqual(st.abort_seq, 3)

    def test_abort_not_running_rejected(self):
        exp = _exp()
        _define(exp)
        with self.assertRaises(ExperimentStateError):
            exp.abort("e1", seq=2)

    def test_abort_unknown_rejected(self):
        exp = _exp()
        with self.assertRaises(UnknownExperimentError):
            exp.abort("nope", seq=1)

    def test_complete_happy_path(self):
        exp = _exp()
        _define(exp)
        exp.run("e1", seq=2)
        st = exp.complete("e1", seq=3)
        self.assertEqual(st.state, "completed")
        self.assertEqual(st.run_seq, 2)

    def test_complete_not_running_rejected(self):
        exp = _exp()
        _define(exp)
        with self.assertRaises(ExperimentStateError):
            exp.complete("e1", seq=2)

    def test_run_after_abort_rejected(self):
        exp = _exp()
        _define(exp)
        exp.run("e1", seq=2)
        exp.abort("e1", seq=3)
        with self.assertRaises(ExperimentStateError):
            exp.run("e1", seq=4)


class TestStatusAndViews(unittest.TestCase):
    def test_status_shape(self):
        exp = _exp()
        _define(exp, seq=1)
        st = exp.status("e1")
        self.assertIsInstance(st, ExperimentStatus)
        d = st.as_dict()
        self.assertEqual(d["state"], "defined")
        self.assertEqual(d["definition_seq"], 1)
        self.assertIsNone(d["run_seq"])

    def test_experiment_ids_sorted(self):
        exp = _exp()
        _define(exp, exp_id="zz", seq=1)
        _define(exp, exp_id="aa", seq=2)
        self.assertEqual(exp.experiment_ids(), ("aa", "zz"))

    def test_report_view(self):
        exp = _exp()
        _define(exp)
        report = exp.run("e1", seq=2)
        self.assertEqual(exp.report("e1"), report)

    def test_report_before_run_rejected(self):
        exp = _exp()
        _define(exp)
        with self.assertRaises(UnknownExperimentError):
            exp.report("e1")

    def test_thread_safety(self):
        exp = _exp()
        errors = []

        def worker(n):
            try:
                faults = (FaultSpec("pod-kill", (("duration_seqs", n),)),)
                exp.define(f"exp-{n}", faults, ("a", "b"),
                           BlastRadius(50), seq=n + 1)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors)
        self.assertEqual(len(exp.experiment_ids()), 10)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("defined", "ran", "aborted", "rejected"):
            rec = chaos_experiment_audit_event(kind, seq=1, experiment_id="e1")
            self.assertEqual(rec["format"], AUDIT_FORMAT)
            self.assertEqual(rec["schema"], SCHEMA)
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["experiment_id"], "e1")

    def test_audit_detail(self):
        rec = chaos_experiment_audit_event(
            "rejected", seq=2, experiment_id="e1", detail="over budget")
        self.assertEqual(rec["detail"], "over budget")

    def test_audit_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            chaos_experiment_audit_event("exploded", seq=1)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(ExperimentValidationError):
            chaos_experiment_audit_event("defined", seq=-1)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent / (MODULE + ".py")
        tree = ast.parse(path.read_text())
        allowed = {"__future__", "hashlib", "json", "math", "threading",
                   "dataclasses", "typing", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import chaos_experiment as m
        m.main()


if __name__ == "__main__":
    unittest.main()
