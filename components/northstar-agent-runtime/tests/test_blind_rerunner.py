from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blind_rerunner import (
    AuditorChecksUnavailable,
    BlindCheck,
    BlindRerunnerError,
    build_blind_bundle,
    compare_check_sets,
    extract_auditor_checks,
    run_blind_rerun,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _repo(tmp_path: Path, *, artifact: str | None = None) -> tuple[Path, str, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    # Source code that discusses sealing is allowed; delivery artifacts are not.
    (root / "sealed_attestation.py").write_text("# verifier implementation\n", encoding="utf-8")
    if artifact:
        artifact_path = root / artifact
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text("evidence\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    return root, _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD:app.py")


CLAIM = "Live connections are withdrawn when their authorization lease is revoked."


class TestBlindBundle:
    def test_bundle_contains_only_start_snapshot_reference_and_claim(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        bundle = build_blind_bundle(commit, CLAIM, repo_root=root)
        assert bundle.as_dict() == {
            "schema": "northstar.blind-rerunner-bundle.v1",
            "start_commit": commit,
            "claim": CLAIM,
            "repo_path": str(root.resolve()),
        }

    def test_bundle_rejects_receipt_path(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="receipt"):
            build_blind_bundle(commit, CLAIM, repo_root=root, candidate_material={"receipt.json": "{}"})

    def test_bundle_rejects_seal_path(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="evidence"):
            build_blind_bundle(commit, CLAIM, repo_root=root, candidate_material={"delivery-seal.json": "{}"})

    def test_bundle_rejects_patch_path(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="patch"):
            build_blind_bundle(commit, CLAIM, repo_root=root, candidate_material={"delivery.patch": "diff"})

    def test_bundle_rejects_generic_seal_filename(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="evidence"):
            build_blind_bundle(commit, CLAIM, repo_root=root, candidate_material={"artifacts/seal.json": "{}"})

    def test_bundle_rejects_receipt_reference_in_claim(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="evidence"):
            build_blind_bundle(commit, "See artifacts/receipt.json for details.", repo_root=root)

    def test_bundle_rejects_summary_marker_in_material(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="evidence"):
            build_blind_bundle(
                commit,
                CLAIM,
                repo_root=root,
                candidate_material={"notes.txt": "DELIVERY SUMMARY: tests passed"},
            )

    def test_bundle_rejects_delivery_artifact_tracked_at_start_commit(self, tmp_path):
        root, commit, _ = _repo(tmp_path, artifact="delivery-summary.md")
        with pytest.raises(BlindRerunnerError, match="excluded delivery artifacts"):
            build_blind_bundle(commit, CLAIM, repo_root=root)

    def test_bundle_fails_closed_for_unresolvable_commit(self, tmp_path):
        root, _, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="object id"):
            build_blind_bundle("bad", CLAIM, repo_root=root)


class TestAuditorCheckExtraction:
    def test_extracts_exact_blob_recomputation_checks_from_pins(self, tmp_path):
        root, commit, blob = _repo(tmp_path)
        seal = {
            "schema": "northstar.delivery-seal.v2",
            "start_commit": commit,
            "start_tree_hash": _git(root, "rev-parse", f"{commit}^{{tree}}"),
            "check_inputs_pinned": True,
            "check_inputs_unchanged": True,
            "check_input_pins": [
                {"path": "app.py", "baseline_blob_sha": blob, "current_blob_sha": blob, "unchanged": True}
            ],
        }
        tree_check, check = extract_auditor_checks(seal)
        assert tree_check.id == "pinned-start-tree"
        assert subprocess.run(tree_check.command, shell=True, cwd=root).returncode == 0
        assert check.id == "pinned-input-1:app.py"
        assert check.description == f"Assert app.py has the pinned baseline Git blob {blob}."
        assert subprocess.run(check.command, shell=True, cwd=root).returncode == 0

    def test_extract_rejects_seal_without_a_usable_check_input_list(self):
        with pytest.raises(AuditorChecksUnavailable, match="no usable"):
            extract_auditor_checks(
                {
                    "schema": "northstar.delivery-seal.v2",
                    "start_commit": "a" * 40,
                    "start_tree_hash": "c" * 40,
                    "check_inputs_pinned": True,
                    "check_inputs_unchanged": True,
                    "check_input_pins": [],
                }
            )

    def test_extract_rejects_changed_pinned_input(self):
        with pytest.raises(AuditorChecksUnavailable, match="incomplete or changed"):
            extract_auditor_checks(
                {
                    "schema": "northstar.delivery-seal.v2",
                    "start_commit": "a" * 40,
                    "start_tree_hash": "c" * 40,
                    "check_inputs_pinned": True,
                    "check_inputs_unchanged": True,
                    "check_input_pins": [
                        {"path": "app.py", "baseline_blob_sha": "b" * 40, "unchanged": False}
                    ],
                }
            )


class TestCheckComparison:
    def test_compare_identifies_known_overlap(self):
        blind = BlindCheck("b1", "Assert status is healthy.", "python check.py --status")
        auditor = BlindCheck("a1", "assert status is healthy.", "python   check.py '--status'")
        report = compare_check_sets([blind], [auditor])
        assert report.blind_only == ()
        assert report.auditor_only == ()
        assert report.both == ({"blind": blind, "auditor": auditor},)

    def test_compare_names_divergence_without_verdict(self):
        blind_only = BlindCheck("b1", "Assert revoked sockets are closed.", "pytest tests/test_revocation.py")
        auditor_only = BlindCheck("a1", "Assert pinned inputs are unchanged.", "git diff --exit-code HEAD")
        shared_blind = BlindCheck("b2", "Assert client errors are surfaced.", "pytest tests/test_client.py")
        shared_auditor = BlindCheck("a2", "assert client errors are surfaced.", "pytest   tests/test_client.py")
        report = compare_check_sets([blind_only, shared_blind], [auditor_only, shared_auditor])
        assert report.blind_only == (blind_only,)
        assert report.auditor_only == (auditor_only,)
        assert report.both == ({"blind": shared_blind, "auditor": shared_auditor},)
        assert report.as_dict()["judgment"] == "operator_review_required"

    def test_compare_collapses_duplicate_normalized_checks(self):
        first = BlindCheck("b1", "assert file is valid", "python verify.py")
        duplicate = BlindCheck("b2", " ASSERT   FILE IS VALID ", "python   verify.py")
        report = compare_check_sets([first, duplicate], [])
        assert report.blind_only == (first,)

    def test_report_shape_serializes_check_records_and_empty_categories(self):
        check = BlindCheck("b", "Assert the command succeeds.", "true")
        payload = compare_check_sets([check], []).as_dict()
        assert set(payload) == {
            "schema", "judgment", "auditor_available", "blind_only", "auditor_only",
            "both", "unassessed_blind", "findings",
        }
        assert payload["blind_only"] == [check.as_dict()]
        assert payload["auditor_only"] == payload["both"] == []
        assert "pass" not in payload["judgment"] and "fail" not in payload["judgment"]

    def test_missing_auditor_seal_keeps_blind_checks_unassessed_not_false_divergence(self, tmp_path):
        root, commit, _ = _repo(tmp_path)
        blind = BlindCheck("b", "Assert the command succeeds.", "true")
        _, report = run_blind_rerun(
            start_commit=commit,
            claim=CLAIM,
            repo_root=root,
            blind_checks=[blind],
            delivery=None,
        )
        payload = report.as_dict()
        assert payload["auditor_available"] is False
        assert payload["blind_only"] == []
        assert payload["unassessed_blind"] == [blind.as_dict()]
        assert "not supplied" in payload["findings"][0]

    def test_slice6_blind_acceptance_checks_and_missing_seal_are_reported(self, tmp_path):
        repo = Path(__file__).resolve().parents[3]
        end_commit = _git(repo, "rev-parse", "a08c983a85acb7175b3987291138653b04f79522^{commit}")
        start_commit = _git(repo, "rev-parse", f"{end_commit}^")
        claim = (
            "This delivery revokes live sockets when authorization leases are withdrawn "
            "and surfaces termination and network errors."
        )
        checks = (
            BlindCheck(
                "blind-sidecar-suite",
                "Assert the egress sidecar tests cover lease withdrawal and live-connection termination.",
                "python3 -m pytest --collect-only -q components/northstar-egress-sidecar/tests",
            ),
            BlindCheck(
                "blind-client-suite",
                "Assert the egress client tests cover surfaced network failures.",
                "env PYTHONPATH=components/northstar-agent-runtime python3 -m pytest --collect-only -q components/northstar-agent-runtime/tests/test_egress_client.py",
            ),
        )

        bundle = build_blind_bundle(start_commit, claim, repo_root=repo)
        assert set(bundle.as_dict()) == {"schema", "start_commit", "claim", "repo_path"}
        assert not any(word in json.dumps(bundle.as_dict()).casefold() for word in ("delivery-seal.json", "receipt.json", "patch.diff", "delivery-summary"))
        end_snapshot = tmp_path / "slice6-end"
        end_snapshot.mkdir()
        archive = subprocess.run(
            ["git", "-C", str(repo), "archive", end_commit], check=True, capture_output=True
        ).stdout
        subprocess.run(["tar", "-x", "-C", str(end_snapshot)], input=archive, check=True)
        for check in checks:
            result = subprocess.run(shlex.split(check.command), cwd=end_snapshot, capture_output=True, text=True)
            assert result.returncode == 0, result.stdout + result.stderr

        report_path = tmp_path / "slice6-divergence.json"
        _, report = run_blind_rerun(
            start_commit=start_commit,
            claim=claim,
            repo_root=repo,
            blind_checks=checks,
            delivery=None,
            report_path=report_path,
        )
        persisted = json.loads(report_path.read_text(encoding="utf-8"))
        assert persisted == report.as_dict()
        assert persisted["auditor_available"] is False
        assert [item["id"] for item in persisted["unassessed_blind"]] == [item.id for item in checks]
        assert "delivery seal was not supplied" in persisted["findings"]
        assert persisted["blind_only"] == []


class TestTheInputValidationIsExercised:
    """The seven input-validation branches the census could not kill.

    Measured 2026-11-25: the whole-file census over
    ``blind_rerunner.py`` reported **killed 13/13** -- a perfect score.
    It was FALSE.  The module's only referencing suite,
    ``test_blind_runner.py``, reads the REPO ROOT (it runs ``git
    rev-parse`` on a named commit), and the census worktree did not
    carry the repository -- so the suite FAILED on the PRISTINE source,
    and every non-zero exit was read as "mutant killed".  With the
    worktree fixed, the same tree reads **killed 6/13**: seven
    survivors, which are seven branches that reject malformed input and
    were never exercised with malformed input.

    Each test below drives the branch with the malformed input it
    exists to reject.  The mutants are the ``or`` -> ``and`` flips that
    let the malformed value THROUGH, so a test that pins the rejection
    kills them.
    """

    def test_a_blind_check_rejects_an_empty_id(self):
        """``or@47``: a check's id must be a non-empty single-line string."""
        with pytest.raises(BlindRerunnerError, match="id must be a non-empty"):
            BlindCheck("", "Assert the status is healthy.", "python check.py")

    def test_a_blind_check_rejects_a_blank_description(self):
        """``or@47``: the same rule, applied to the description."""
        with pytest.raises(BlindRerunnerError, match="description must be a non-empty"):
            BlindCheck("b1", "   ", "python check.py")

    def test_a_blind_check_rejects_a_multiline_command(self):
        """``or@47``: the same rule, applied to the command."""
        with pytest.raises(BlindRerunnerError, match="command must be a non-empty"):
            BlindCheck("b1", "Assert the status is healthy.", "python check.py\nrm -rf /")

    def test_a_claim_must_be_a_single_trimmed_sentence(self, tmp_path):
        """``or@183``: the claim's own validation.

        Two of the disjuncts are untested: the TRIMMED rule
        (``claim != claim.strip()``) and the SINGLE-SENTENCE rule.  A
        claim with trailing whitespace, or with two sentences, must be
        rejected.
        """
        # The start commit must be VALID, or the check ABOVE this one
        # fires first and the claim's own check is never reached -- which
        # is how the mutant survived the first version of this test.
        root, commit, _ = _repo(tmp_path)
        # The EMPTY claim is the input that distinguishes the two
        # operands.  The mutation flips the FIRST ``or`` to ``and``, so
        # the two forms differ only when ``not isinstance(claim, str)``
        # and ``not claim.strip()`` DISAGREE -- and with an empty claim
        # the third disjunct (``claim != claim.strip()``) is also False,
        # so it cannot mask the difference.
        #
        # (A whitespace-only claim does NOT work: ``"   " != ""`` makes
        # the third disjunct raise anyway, so both forms reject it and
        # the mutant survives.  That was the first version of this
        # test, and it passed for the wrong reason.)
        with pytest.raises(BlindRerunnerError, match="claim must be a non-empty"):
            build_blind_bundle(commit, "", repo_root=root)
        with pytest.raises(BlindRerunnerError, match="exactly one sentence"):
            build_blind_bundle(commit, CLAIM + " And another one.", repo_root=root)

    def test_candidate_material_paths_must_be_strings(self, tmp_path):
        """``or@200``: a non-string path or content is malformed input.

        The existing tests pass a string path with an EXCLUDED name --
        which the evidence-path check rejects first.  They never pass a
        path that is not a string at all.
        """
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="paths and contents must be strings"):
            build_blind_bundle(
                commit, CLAIM, repo_root=root, candidate_material={123: "content"}
            )

    def test_candidate_material_in_an_evidence_DIRECTORY_is_rejected(self, tmp_path):
        """``retT@163``: an evidence DIRECTORY is excluded, not just a name.

        The module excludes two shapes of delivery artifact: a path whose
        BASENAME is a known evidence name (``delivery-seal.json`` and
        friends), and a path that lies inside an evidence DIRECTORY
        (``delivery-evidence/...``).  Only the first shape was tested,
        and the text check does NOT catch the second -- it looks for
        markers, not directory names -- so the directory check was the
        only thing standing between an evidence directory and a bundle.
        """
        root, commit, _ = _repo(tmp_path)
        with pytest.raises(BlindRerunnerError, match="excluded delivery evidence path"):
            build_blind_bundle(
                commit,
                CLAIM,
                repo_root=root,
                candidate_material={"delivery-evidence/notes.txt": "x"},
            )
        with pytest.raises(BlindRerunnerError, match="excluded delivery evidence path"):
            build_blind_bundle(
                commit,
                CLAIM,
                repo_root=root,
                candidate_material={"evidence_bundle/report.md": "x"},
            )

    def test_a_seal_without_both_pins_is_unavailable(self):
        """``or@232``: both pins must hold.

        The existing test supplies an empty pin LIST, which the next
        check rejects.  It never supplies a seal whose
        ``check_inputs_unchanged`` is False -- so the second disjunct is
        untested.
        """
        with pytest.raises(AuditorChecksUnavailable, match="unchanged pinned check inputs"):
            extract_auditor_checks(
                {
                    "schema": "northstar.delivery-seal.v2",
                    "start_commit": "a" * 40,
                    "start_tree_hash": "c" * 40,
                    "check_inputs_pinned": True,
                    "check_inputs_unchanged": False,
                    "check_input_pins": [
                        {"path": "app.py", "baseline_blob_sha": "b" * 40, "unchanged": True}
                    ],
                }
            )

    def test_a_seal_with_an_unusable_start_commit_is_unavailable(self):
        """``or@237``: the start commit must be a full Git object id.

        The existing tests always supply ``"a" * 40``, which MATCHES the
        pattern, so the rejection never fires.  A short or non-hex
        commit must be rejected.
        """
        with pytest.raises(AuditorChecksUnavailable, match="no valid start commit"):
            extract_auditor_checks(
                {
                    "schema": "northstar.delivery-seal.v2",
                    "start_commit": "not-a-commit",
                    "start_tree_hash": "c" * 40,
                    "check_inputs_pinned": True,
                    "check_inputs_unchanged": True,
                    "check_input_pins": [
                        {"path": "app.py", "baseline_blob_sha": "b" * 40, "unchanged": True}
                    ],
                }
            )

    def test_a_seal_with_an_unusable_tree_hash_is_unavailable(self):
        """``or@239``: the tree hash must be a usable digest.

        ``"c" * 40`` is hex and 40 long, so it MATCHES.  A short or
        non-hex tree hash must be rejected.
        """
        with pytest.raises(AuditorChecksUnavailable, match="no usable pinned start-tree hash"):
            extract_auditor_checks(
                {
                    "schema": "northstar.delivery-seal.v2",
                    "start_commit": "a" * 40,
                    "start_tree_hash": "zz",
                    "check_inputs_pinned": True,
                    "check_inputs_unchanged": True,
                    "check_input_pins": [
                        {"path": "app.py", "baseline_blob_sha": "b" * 40, "unchanged": True}
                    ],
                }
            )
