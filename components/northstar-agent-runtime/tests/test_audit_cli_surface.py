"""The `northstar audit` CLI's command surface, exercised at the CLI.

WHY THIS FILE EXISTS (measured 2026-11-25)
------------------------------------------
The mutant census scores `audit_cli.py` at 6/31 at the single-suite
scope (the artifact's row names `tests/test_akf_export.py`) and 11/31
at the union scope, and the survivors are all in the COMMAND DISPATCH
-- the parts of `run_audit` that turn a command line into a decision:

    or@520  anchor:      `args.anchored_at or None`
    lt@536  verify:      `args.clock_skew < 0`
    or@542  verify:      `args.expect_session_id or None`
    or@543  verify:      `args.expect_run_id or None`
    and@549  verify:     `args.anchor and result.ok`
    and@566  verify:     `args.external_anchor and result.ok`
    or@585  verify:      `args.rekor_url or None`
    or@603  verify:      `anchor_failed or result.broken_at is not None`
    and@628 verify:      `args.anchor and result.anchor_ok is not None`
    eq@639  verify:      `status == "INVALID"`
    or@659  anchor-ext:  `args.rekor_url or REKOR_V1_DEFAULT`
    or@677  verify-arch: `args.rekor_url or None`
    or@744  export --akf:  `args.subject or None`
    or@745  export --akf:  `args.model_id or None`
    and@795 export --trace: `seed is not None and len(seed) != 32`
    or@801..805 export --trace: the five `or None` fallbacks
    and@848 export --scitt: `seed is not None and len(seed) != 32`
    or@851  export --scitt: `args.key_id or ""`
    and@852 export --scitt: `not key_id and seed is not None`

The suites that reach this module tested only ONE of its nine commands
(`export`), and only its happy path.  The other eight -- `keygen`,
`anchor`, `verify`, `anchor-external`, `verify-archive`, `seal-head`,
`check-head`, `export --scitt` -- and every option-validation branch
were never driven from a command line at all.

The rule is §31's and §32's, in its third form:

> **A guard needs a crafted input.**
>
> Here the crafted input is a COMMAND LINE.  A CLI that is only ever
> exercised on its happy path has an untested decision at every
> `or`/`and` that decides what an OPTION MEANS, and the `or None`
> fallbacks are exactly that: each one decides whether an empty string
> becomes `None` (meaning "not specified") or stays `""` (meaning
> "specified, and empty").  Those two are different to the code that
> receives them, and only a command line can tell them apart.

So this file drives the CLI with the option combinations that decide
each of those branches, and asserts the exit code AND the output.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401


def _chained_feed(path: Path, n: int = 3) -> Path:
    """A small chained audit feed (chain v2)."""
    from audit_chain import chain_records

    records = [
        {
            "schema_version": "audit.ndjson/1",
            "component": "northstar-agent-runtime",
            "event": "assistant",
            "seq": i,
            "ts": f"2026-10-03T10:00:0{i}.000Z",
            "level": "info",
            "payload": {"i": i},
        }
        for i in range(1, n + 1)
    ]
    chained = chain_records(
        records, component="northstar-agent-runtime", session_id="s-1"
    )
    path.write_text(
        "\n".join(
            json.dumps(r, sort_keys=True, separators=(",", ":")) for r in chained
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _run(args: argparse.Namespace) -> tuple[int, str, str]:
    """Run ``run_audit`` and capture (rc, stdout, stderr)."""
    from audit_cli import run_audit

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_audit(args)
    return rc, out.getvalue(), err.getvalue()


class _Args(argparse.Namespace):
    """Build an args namespace with every option this CLI knows."""

    @classmethod
    def for_verify(cls, feed, **kwargs):
        base = dict(
            audit_command="verify",
            feed=str(feed),
            pubkey="",
            expect_session_id="",
            expect_run_id="",
            strict=False,
            clock_skew=0,
            anchor="",
            external_anchor="",
            rekor_url="",
            json=False,
            allow_clock_skew=False,
            enforce_causality=False,
            check_timestamps=False,
            require_signed=False,
        )
        base.update(kwargs)
        return cls(**base)


class _StubbedRekor:
    """Stand in for the Rekor transport so no test touches the network.

    ``audit_rekor``'s client is the module-level ``_post_json``, and
    every command that talks to the log goes through it.  Replacing it
    with a stub that RECORDS the url and then fails the way an
    unreachable network fails does two things:

    * the test is hermetic -- it cannot depend on whether the public
      log happens to be reachable, and it cannot publish an entry into
      a third party's transparency log as a side effect of running the
      suite;
    * the recorded url IS the observable the ``or None`` /
      ``or REKOR_V1_DEFAULT`` fallbacks decide, so the assertion is on
      which log the command tried, not on a network error's wording.
    """

    def __init__(self):
        self.urls: list[str] = []

    def __enter__(self):
        import audit_rekor

        self._real = audit_rekor._post_json

        def _fake(url, payload, *, timeout):
            self.urls.append(url)
            raise audit_rekor.RekorError(f"cannot reach {url}: network disabled in tests")

        audit_rekor._post_json = _fake
        return self

    def __exit__(self, *_exc):
        import audit_rekor

        audit_rekor._post_json = self._real
        return False


class VerifyCommandTests(unittest.TestCase):
    """The `verify` command's option handling."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_negative_clock_skew_is_a_usage_error(self):
        # `args.clock_skew < 0` -- a NEGATIVE skew must be refused before
        # the feed is read.  With `<= 0` a skew of exactly ZERO would be
        # refused too, which is the boundary the suite never reaches.
        rc, _out, err = _run(_Args.for_verify(self.feed, clock_skew=-1))
        self.assertEqual(rc, 64)
        self.assertIn("clock-skew", err)

    def test_a_zero_clock_skew_is_accepted(self):
        # The other side of the same boundary: a skew of exactly ZERO is
        # legal, and it is what every other test here uses.
        rc, _out, _err = _run(_Args.for_verify(self.feed, clock_skew=0))
        self.assertEqual(rc, 0)

    def test_an_empty_session_id_is_not_specified(self):
        # `args.expect_session_id or None` -- an EMPTY string must
        # become `None` ("not specified"), not stay `""` ("specified,
        # and empty").  The two are different to the verifier: the feed's
        # session id is "s-1", so expecting "" must not match it.
        rc, _out, _err = _run(_Args.for_verify(self.feed, expect_session_id=""))
        self.assertEqual(rc, 0)

    def test_a_wrong_session_id_is_refused(self):
        # The other side: a session id that was actually specified must
        # be CHECKED.  If `or None` swallowed a non-empty value, this
        # would wrongly pass.
        rc, out, err = _run(_Args.for_verify(self.feed, expect_session_id="s-2"))
        self.assertNotEqual(rc, 0)
        self.assertIn("s-2", out + err)

    def test_a_wrong_run_id_is_refused(self):
        # Same for `args.expect_run_id or None`.
        rc, _out, err = _run(_Args.for_verify(self.feed, expect_run_id="run-2"))
        self.assertNotEqual(rc, 0)

    def test_a_missing_anchor_manifest_is_a_usage_error(self):
        # `args.anchor and result.ok` -- the anchor is read only when
        # the feed verified.  A MISSING anchor file is a usage error.
        rc, _out, err = _run(
            _Args.for_verify(self.feed, anchor=str(self.dir / "nope.json"))
        )
        self.assertEqual(rc, 64)
        self.assertIn("anchor", err)

    def test_a_matching_anchor_manifest_verifies(self):
        from audit_chain import anchor_manifest

        manifest = anchor_manifest(self.feed)
        anchor = self.dir / "anchor.json"
        anchor.write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, _err = _run(_Args.for_verify(self.feed, anchor=str(anchor)))
        self.assertEqual(rc, 0)

    def test_a_stale_anchor_manifest_breaks_the_feed(self):
        # The anchor's WHOLE POINT: a feed that was rewritten after it
        # was anchored must not verify.  Without this, the `--anchor`
        # option could be dropped from the CLI and nothing would notice.
        from audit_chain import anchor_manifest

        manifest = anchor_manifest(self.feed)
        anchor = self.dir / "anchor.json"
        anchor.write_text(json.dumps(manifest), encoding="utf-8")
        # Rewrite the feed after anchoring it.
        self.feed.write_text(
            self.feed.read_text(encoding="utf-8") + "\n", encoding="utf-8"
        )
        rc, _out, _err = _run(_Args.for_verify(self.feed, anchor=str(anchor)))
        self.assertNotEqual(rc, 0)

    def test_a_missing_external_anchor_record_is_a_usage_error(self):
        # `args.external_anchor` -- the external anchor record must be
        # READABLE.  A missing file is a usage error, not a mismatch.
        rc, _out, err = _run(
            _Args.for_verify(self.feed, external_anchor=str(self.dir / "nope.json"))
        )
        self.assertEqual(rc, 64)
        self.assertIn("external anchor", err)

    def test_a_missing_feed_is_refused(self):
        # `verify` has NO missing-feed guard of its own: it passes the
        # path straight to `verify_file`, which reports the unreadable
        # feed as INVALID (exit 3).  The guard that DOES exist is on
        # `anchor` (see AnchorCommandTests).
        rc, out, _err = _run(_Args.for_verify(self.dir / "missing.ndjson"))
        self.assertNotEqual(rc, 0)
        self.assertIn("audit verify:", out)


class KeygenCommandTests(unittest.TestCase):
    """The `keygen` command."""

    def test_keygen_emits_a_seed_and_a_pubkey(self):
        rc, out, _err = _run(argparse.Namespace(audit_command="keygen", json=False))
        self.assertEqual(rc, 0)
        self.assertIn("seed_hex:", out)
        self.assertIn("pubkey_hex:", out)

    def test_keygen_json_emits_one_object(self):
        rc, out, _err = _run(argparse.Namespace(audit_command="keygen", json=True))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["seed_hex"]), 64)
        self.assertEqual(len(payload["pubkey_hex"]), 64)


class AnchorCommandTests(unittest.TestCase):
    """The `anchor` command."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def test_anchor_writes_a_manifest(self):
        out = self.dir / "manifest.json"
        rc, stdout, _err = _run(
            argparse.Namespace(
                audit_command="anchor",
                feed=str(self.feed),
                out=str(out),
                anchored_at="",
            )
        )
        self.assertEqual(rc, 0)
        self.assertIn("anchored", stdout)
        manifest = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(manifest["anchor"], "northstar-audit-anchor/1")
        self.assertEqual(manifest["records"], 3)

    def test_anchor_records_the_anchored_at_when_given(self):
        # `args.anchored_at or None` -- a GIVEN timestamp is recorded; an
        # absent one is NOT, and the two are different to the manifest.
        out = self.dir / "manifest.json"
        rc, _stdout, _err = _run(
            argparse.Namespace(
                audit_command="anchor",
                feed=str(self.feed),
                out=str(out),
                anchored_at="2026-10-03T11:00:00Z",
            )
        )
        self.assertEqual(rc, 0)
        manifest = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(manifest["anchored_at"], "2026-10-03T11:00:00Z")

    def test_anchor_omits_anchored_at_when_absent(self):
        out = self.dir / "manifest.json"
        rc, _stdout, _err = _run(
            argparse.Namespace(
                audit_command="anchor",
                feed=str(self.feed),
                out=str(out),
                anchored_at="",
            )
        )
        self.assertEqual(rc, 0)
        manifest = json.loads(out.read_text(encoding="utf-8"))
        self.assertNotIn("anchored_at", manifest)

    def test_anchor_on_a_missing_feed_is_a_usage_error(self):
        rc, _out, err = _run(
            argparse.Namespace(
                audit_command="anchor",
                feed=str(self.dir / "missing.ndjson"),
                out=str(self.dir / "m.json"),
                anchored_at="",
            )
        )
        self.assertEqual(rc, 64)
        self.assertIn("no such feed file", err)


class VerifyArchiveCommandTests(unittest.TestCase):
    """The `verify-archive` command's argument handling."""

    def test_verify_archive_on_a_missing_directory_is_refused(self):
        # `verify_archive` reports the failure in its RESULT, not on
        # stderr: the command prints a BROKEN line and exits 1.
        rc, out, err = _run(
            argparse.Namespace(
                audit_command="verify-archive",
                directory=str(Path(self._tmp()) / "nope"),
                online=False,
                json=False,
                rekor_url="",
            )
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("BROKEN", out + err)

    @staticmethod
    def _tmp():
        import tempfile as _t

        holder = _t.TemporaryDirectory()
        return holder.name


class ExportOptionTests(unittest.TestCase):
    """The `export` command's `or None` fallbacks."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, **kwargs):
        base = dict(
            audit_command="export",
            feed=str(self.feed),
            trace=False,
            akf=True,
            label="internal",
            model_id="",
            subject="",
            seed_hex="",
            out="",
            policy_bundle_hash="",
            data_class="",
            model_provider="",
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_export_with_no_optional_labels_still_writes(self):
        # `args.subject or None`, `args.model_id or None`, and the four
        # others: an EMPTY option must become None (absent), not "" (set
        # and empty).  The export must still be well-formed, and the
        # absent options must be ABSENT from the unit.
        out = self.dir / "unit.json"
        rc, _stdout, _err = _run(self._args(out=str(out)))
        self.assertEqual(rc, 0)
        unit = json.loads(out.read_text(encoding="utf-8"))
        self.assertNotIn("model", unit)
        # With no subject, the unit falls back to a feed-derived id.
        self.assertTrue(unit["id"].startswith("akf:northstar:"))

    def test_export_with_a_subject_carries_it(self):
        # The other side of `args.subject or None`: a GIVEN subject
        # becomes the unit's id.
        out = self.dir / "unit.json"
        rc, _stdout, _err = _run(self._args(out=str(out), subject="team-a"))
        self.assertEqual(rc, 0)
        unit = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(unit["id"], "team-a")

    def test_export_with_a_model_id_carries_it(self):
        # `args.model_id or None` -- a given model id becomes the unit's
        # top-level "model"; an absent one leaves the key out entirely.
        out = self.dir / "unit.json"
        rc, _stdout, _err = _run(self._args(out=str(out), model_id="model-x"))
        self.assertEqual(rc, 0)
        unit = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(unit["model"], "model-x")


def _external_anchor_record(feed: Path, seed: bytes, **overrides):
    """Build a REAL Rekor anchor record for ``feed``, offline.

    ``audit_rekor.anchor_feed_head`` submits to the network, so the
    record is assembled here from the same primitives: the canonical
    anchor statement, its PAE-signed DSSE signature, and the digests.
    Only ``log_index``/``integrated_time``/``uuid`` are invented, and
    nothing in the offline verification path reads them.
    """
    import base64
    import hashlib

    from audit_chain import anchor_manifest
    from audit_rekor import (
        ANCHOR_RECORD_VERSION,
        PAYLOAD_TYPE,
        REKOR_API,
        REKOR_V1_DEFAULT,
        anchor_statement,
        pae,
    )
    from ed25519 import public_key as ed_public_key
    from ed25519 import sign as ed_sign

    manifest = anchor_manifest(feed)
    payload = anchor_statement(
        feed_sha256=manifest["feed_sha256"],
        head_chain_hash=manifest["head_chain_hash"],
        records=manifest["records"],
        anchored_at="2026-10-03T11:00:00Z",
    )
    signature = ed_sign(seed, pae(PAYLOAD_TYPE, payload))
    record = {
        "anchor": ANCHOR_RECORD_VERSION,
        "rekor_url": REKOR_V1_DEFAULT,
        "rekor_api": REKOR_API,
        "entry_kind": "dsse",
        "uuid": "0" * 32,
        "log_index": 1,
        "integrated_time": 1_700_000_000,
        "payload_type": PAYLOAD_TYPE,
        "payload": json.loads(payload.decode("utf-8")),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "envelope_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "pubkey": ed_public_key(seed).hex(),
        "trust": "docs/concepts/audit-proof-spec.md#external-anchoring-via-rekor",
    }
    record.update(overrides)
    return record


class VerifyStatusSelectionTests(unittest.TestCase):
    """`run_audit`'s CHOICE of status, and the exit code that follows.

    ```
    if result.ok:                      status = "OK"
    elif result.unprotected:            status = "UNPROTECTED"
    elif anchor_failed or result.broken_at is not None:
                                       status = "BROKEN"
    else:                              status = "INVALID"
    ...
    if status == "INVALID":             return 3
    ```

    Four statuses, four different exit codes, and the branches are
    chosen by DIFFERENT conditions: `ok`, `unprotected`, `anchor_failed`
    (the anchor path sets it) and `broken_at` (the chain path sets it).
    A suite that only ever verifies a good feed reaches exactly ONE of
    the four.

    The crafted input for each is a different kind of damaged feed:
    a feed with no chain fields at all (UNPROTECTED), a feed whose
    chain does not link (BROKEN via ``broken_at``), a feed whose bytes
    differ from an anchor manifest (BROKEN via ``anchor_failed``, with
    ``broken_at`` still None), and a feed that is not JSON at all
    (INVALID: ``broken_at`` is None and nothing else fails).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_good_feed_verifies_ok(self):
        rc, out, _err = _run(_Args.for_verify(self.feed))
        self.assertEqual(rc, 0)
        self.assertIn("OK", out)

    def test_an_unprotected_feed_is_reported_unprotected(self):
        # A feed with NO chain fields: `result.unprotected` is set and
        # `broken_at` is None, so this is the UNPROTECTED branch and
        # NOT the INVALID branch.
        legacy = self.dir / "legacy.ndjson"
        legacy.write_text(
            json.dumps({"event": "assistant", "seq": 1}) + "\n", encoding="utf-8"
        )
        rc, out, _err = _run(_Args.for_verify(legacy))
        self.assertEqual(rc, 2)
        self.assertIn("UNPROTECTED", out)

    def test_a_broken_chain_is_reported_broken(self):
        # A feed whose chain does not link: `broken_at` is set, so the
        # status is BROKEN and the exit code is 1 (not 3).
        broken = self.dir / "broken.ndjson"
        lines = self.feed.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        record["chain_hash"] = "sha256:" + "00" * 32
        broken.write_text(
            "\n".join(lines[:-1] + [json.dumps(record, sort_keys=True)]) + "\n",
            encoding="utf-8",
        )
        rc, out, _err = _run(_Args.for_verify(broken))
        self.assertEqual(rc, 1)
        self.assertIn("BROKEN", out)

    def test_an_unreadable_feed_is_reported_invalid(self):
        # A feed that is not JSON at all: `broken_at` is None (the
        # parse failure is reported with `reason` only), nothing is
        # unprotected, no anchor failed -- so this is the INVALID branch
        # and the exit code is 3.
        junk = self.dir / "junk.ndjson"
        junk.write_text("this is not json\n", encoding="utf-8")
        rc, out, _err = _run(_Args.for_verify(junk))
        self.assertEqual(rc, 3)
        self.assertIn("INVALID", out)

    def test_a_rewritten_feed_against_its_anchor_is_reported_broken(self):
        # `anchor_failed` -- the THIRD condition of the same elif.  The
        # feed's chain is still intact (`broken_at` is None) but its
        # BYTES differ from the anchored snapshot, so only the anchor
        # can see it.  Without this test the `anchor_failed or ...`
        # disjunction has one of its two operands unmeasured.
        from audit_chain import anchor_manifest

        manifest = anchor_manifest(self.feed)
        anchor = self.dir / "anchor.json"
        anchor.write_text(json.dumps(manifest), encoding="utf-8")
        # Append a byte: the chain still verifies (the extra byte is
        # after the last record), but the file's bytes no longer match.
        self.feed.write_text(
            self.feed.read_text(encoding="utf-8") + "\n", encoding="utf-8"
        )
        rc, out, _err = _run(_Args.for_verify(self.feed, anchor=str(anchor)))
        self.assertEqual(rc, 1)
        self.assertIn("BROKEN", out)

    def test_no_anchor_note_when_the_feed_failed_before_the_anchor_ran(self):
        # `args.anchor and result.anchor_ok is not None` -- the anchor
        # check runs ONLY when the feed verified (`if args.anchor and
        # result.ok`).  So when the feed is BROKEN the anchor manifest
        # is never read, `result.anchor_ok` stays None, and there is NO
        # anchor note to print.
        #
        # The mutant `and -> or` turns this into
        # `args.anchor or result.anchor_ok is not None`, which is TRUE
        # whenever an anchor was given -- and prints an EMPTY note
        # ("; anchor: ") for a feed that never reached the anchor
        # check.  The note's presence is the observable.
        from audit_chain import anchor_manifest

        manifest = anchor_manifest(self.feed)
        anchor = self.dir / "anchor.json"
        anchor.write_text(json.dumps(manifest), encoding="utf-8")
        broken = self.dir / "broken.ndjson"
        lines = self.feed.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[-1])
        record["chain_hash"] = "sha256:" + "00" * 32
        broken.write_text(
            "\n".join(lines[:-1] + [json.dumps(record, sort_keys=True)]) + "\n",
            encoding="utf-8",
        )
        rc, out, _err = _run(_Args.for_verify(broken, anchor=str(anchor)))
        self.assertEqual(rc, 1)
        self.assertIn("BROKEN", out)
        self.assertNotIn("anchor:", out)

    def test_the_anchor_note_is_shown_when_an_anchor_was_given(self):
        # `args.anchor and result.anchor_ok is not None` -- the anchor
        # note is printed ONLY when an anchor was given AND the check
        # actually ran.  With no anchor, no note.
        from audit_chain import anchor_manifest

        manifest = anchor_manifest(self.feed)
        anchor = self.dir / "anchor.json"
        anchor.write_text(json.dumps(manifest), encoding="utf-8")
        rc, out, _err = _run(_Args.for_verify(self.feed, anchor=str(anchor)))
        self.assertEqual(rc, 0)
        self.assertIn("anchor:", out)
        # And with no anchor at all, there is no note.
        rc, out, _err = _run(_Args.for_verify(self.feed))
        self.assertEqual(rc, 0)
        self.assertNotIn("anchor:", out)


class ExternalAnchorVerifyTests(unittest.TestCase):
    """`verify --external-anchor`: the offline check and the log check.

    ```
    ok, external_note = verify_anchor_offline(external_record, head_chain_hash=head_now)
    if ok:
        ok, external_note = verify_anchor_in_log(
            external_record,
            rekor_url=args.rekor_url or None,
        )
    ```

    The `or None` at the end decides WHICH log the entry is looked up
    in: ``None`` means "use the anchor record's own ``rekor_url``, and
    fall back to the public log".  A non-empty ``--rekor-url`` OVERRIDES
    it.  The two are different, and the difference is visible in the
    URL the client tries.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")
        self.seed = bytes(range(32))
        self.anchor = self.dir / "external.json"
        self.anchor.write_text(
            json.dumps(_external_anchor_record(self.feed, self.seed)),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_an_external_anchor_for_this_feed_passes_the_offline_check(self):
        # The offline check passes, so the command proceeds to the LOG
        # check.  With the transport stubbed, the log cannot be reached,
        # so the exit code is 5 (EXTERNAL_UNVERIFIED) -- which is what
        # proves it got that far: the offline check did NOT report a
        # mismatch.
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(
                _Args.for_verify(self.feed, external_anchor=str(self.anchor))
            )
        self.assertEqual(rc, 5)
        self.assertIn("cannot reach transparency log", err)
        self.assertEqual(len(rekor.urls), 1)

    def test_an_external_anchor_for_another_head_is_a_mismatch(self):
        # The offline check FAILS, so the log is never consulted and the
        # feed is reported as BROKEN with the mismatch reason.
        other = _chained_feed(self.dir / "other.ndjson", n=4)
        self.anchor.write_text(
            json.dumps(_external_anchor_record(other, self.seed)), encoding="utf-8"
        )
        rc, out, _err = _run(
            _Args.for_verify(self.feed, external_anchor=str(self.anchor))
        )
        self.assertNotEqual(rc, 0)
        self.assertIn("external anchor", out + _err)

    def test_the_rekor_url_override_reaches_the_client(self):
        # `args.rekor_url or None` -- a GIVEN url must REPLACE the
        # anchor record's own url.  The url the client was handed is
        # the observable: with the fallback collapsed to "" the client
        # would try the anchor record's url (the public log) instead.
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(
                _Args.for_verify(
                    self.feed,
                    external_anchor=str(self.anchor),
                    rekor_url="https://log.example.invalid",
                )
            )
        self.assertEqual(rc, 5)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn("log.example.invalid", rekor.urls[0])

    def test_an_absent_rekor_url_uses_the_anchor_records_own_url(self):
        from audit_rekor import REKOR_V1_DEFAULT

        # With no `--rekor-url`, the anchor record's own url is used
        # (here the public default), so the client is handed THAT host.
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(
                _Args.for_verify(self.feed, external_anchor=str(self.anchor))
            )
        self.assertEqual(rc, 5)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn(REKOR_V1_DEFAULT, rekor.urls[0])


class AnchorExternalTests(unittest.TestCase):
    """`anchor-external`: the seed guards and the log url fallback.

    ```
    feed, seed, rekor_url=args.rekor_url or REKOR_V1_DEFAULT
    ```

    The `or` decides which log the anchor is SUBMITTED to: an absent
    `--rekor-url` must fall back to the public log, not to an empty
    string (which would produce a URL like ``/api/v1/log/entries``).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, **kwargs):
        base = dict(
            audit_command="anchor-external",
            feed=str(self.feed),
            seed_hex="ab" * 32,
            out=str(self.dir / "anchor.json"),
            rekor_url="",
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_a_missing_feed_is_a_usage_error(self):
        rc, _out, err = _run(self._args(feed=str(self.dir / "missing.ndjson")))
        self.assertEqual(rc, 64)
        self.assertIn("no such feed file", err)

    def test_a_non_hex_seed_is_a_usage_error(self):
        rc, _out, err = _run(self._args(seed_hex="zz"))
        self.assertEqual(rc, 64)
        self.assertIn("not valid hex", err)

    def test_a_short_seed_is_a_usage_error(self):
        rc, _out, err = _run(self._args(seed_hex="ab" * 16))
        self.assertEqual(rc, 64)
        self.assertIn("64 hex chars", err)

    def test_an_absent_rekor_url_falls_back_to_the_public_log(self):
        from audit_rekor import REKOR_V1_DEFAULT

        # The url the client was handed is the observable.  With `or ""`
        # the url would be empty and the client would be handed a path
        # with no host.
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(self._args())
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn(REKOR_V1_DEFAULT, rekor.urls[0])

    def test_a_given_rekor_url_replaces_the_default(self):
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(self._args(rekor_url="https://log.example.invalid"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn("log.example.invalid", rekor.urls[0])


class VerifyArchiveUrlTests(unittest.TestCase):
    """`verify-archive`: the `or None` on the rekor url.

    ```
    result = verify_archive(
        args.directory,
        rekor_url=args.rekor_url or None,
        online=bool(getattr(args, "online", False)),
    )
    ```

    The url only matters with ``--online``.  With no url given, the
    archive's OWN external anchor record names the log; with a url
    given, it overrides.  Both are visible in the failure message.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _archive(self) -> Path:
        from audit_archive import write_archive

        target = self.dir / "archive"
        write_archive(
            target,
            self.feed.read_bytes(),
            session_id="s-1",
            external_anchor=_external_anchor_record(self.feed, bytes(range(32))),
        )
        return target

    def _args(self, **kwargs):
        base = dict(
            audit_command="verify-archive",
            directory=str(self.dir / "archive"),
            online=True,
            json=False,
            rekor_url="",
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_an_intact_archive_verifies_offline(self):
        target = self._archive()
        rc, out, _err = _run(self._args(directory=str(target), online=False))
        self.assertEqual(rc, 0)
        self.assertIn("OK", out)

    def test_the_online_check_uses_the_anchors_own_url(self):
        # No `--rekor-url`: the archive's external anchor record names
        # the log, so the client is handed THAT host.
        from audit_rekor import REKOR_V1_DEFAULT

        target = self._archive()
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(self._args(directory=str(target)))
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn(REKOR_V1_DEFAULT, rekor.urls[0])

    def test_the_online_check_honours_a_rekor_url_override(self):
        target = self._archive()
        with _StubbedRekor() as rekor:
            rc, _out, err = _run(
                self._args(directory=str(target), rekor_url="https://log.example.invalid")
            )
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(rekor.urls), 1)
        self.assertIn("log.example.invalid", rekor.urls[0])


class TraceExportOptionTests(unittest.TestCase):
    """`export --trace`: the five `or None` fallbacks.

    ```
    policy_bundle_hash=args.policy_bundle_hash or None,
    data_class=args.data_class or None,
    subject=args.subject or None,
    model_provider=args.model_provider or None,
    model_id=args.model_id or None,
    ```

    `trace_export.build_trace_record` treats `None` and `""`
    DIFFERENTLY for four of the five.  `None` means "not specified" and
    the key is left out of the record; `""` would be a SPECIFIED EMPTY
    VALUE, and for `policy_bundle_hash` an empty string is not a valid
    `sha256:<hex>` pin and is REFUSED.  So the fallback is load-bearing
    and only a command line can exercise it: `""` reaches the CLI as an
    empty option value, and the fallback must turn it into "absent".
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, **kwargs):
        base = dict(
            audit_command="export",
            feed=str(self.feed),
            trace=True,
            akf=False,
            scitt=False,
            label="internal",
            model_id="",
            subject="",
            seed_hex="",
            out="",
            policy_bundle_hash="",
            data_class="",
            model_provider="",
            rekor_anchor="",
            key_id="",
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_trace_export_with_every_option_empty_succeeds(self):
        # All five options empty: every fallback must yield None, and
        # the export must succeed with none of the optional keys present.
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(self._args(out=str(out)))
        self.assertEqual(rc, 0, err)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertNotIn("model", record)
        self.assertNotIn("data_class", record)
        self.assertNotIn("bundle_hash", record["policy"])

    def test_trace_export_carries_the_subject(self):
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(self._args(out=str(out), subject="did:x:1"))
        self.assertEqual(rc, 0, err)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["subject"], "did:x:1")

    def test_trace_export_carries_the_model_identity(self):
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(
            self._args(out=str(out), model_provider="acme", model_id="m-1")
        )
        self.assertEqual(rc, 0, err)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["model"]["provider"], "acme")
        self.assertEqual(record["model"]["model_id"], "m-1")

    def test_trace_export_carries_the_policy_bundle_hash(self):
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(
            self._args(out=str(out), policy_bundle_hash="sha256:" + "ab" * 32)
        )
        self.assertEqual(rc, 0, err)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["policy"]["bundle_hash"], "sha256:" + "ab" * 32)

    def test_trace_export_carries_the_data_class(self):
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(self._args(out=str(out), data_class="confidential"))
        self.assertEqual(rc, 0, err)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["data_class"], "confidential")

    def test_trace_export_refuses_an_empty_policy_bundle_hash(self):
        # The EMPTY option must NOT reach the record builder as "",
        # because "" is not a valid `sha256:<hex>` pin.  With `or None`
        # the export succeeds; without it, it would be refused.
        out = self.dir / "trace.json"
        rc, _stdout, err = _run(self._args(out=str(out)))
        self.assertEqual(rc, 0, err)
        self.assertNotIn("bundle_hash", json.loads(out.read_text(encoding="utf-8"))["policy"])


class ScittExportOptionTests(unittest.TestCase):
    """`export --scitt`: the seed guards and the key-id fallback.

    ```
    if seed is not None and len(seed) != 32:   # and@848
    key_id = args.key_id or ""                  # or@851
    if not key_id and seed is not None:         # and@852
    ```

    The first is a conjunction, so BOTH halves must be exercised: a
    `None` seed is not a bad seed, and a 32-byte seed is not a bad
    seed.  The second is the `or ""` fallback, and the third is what
    turns a derived pubkey into the key id.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = _chained_feed(self.dir / "feed.ndjson")

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self, **kwargs):
        base = dict(
            audit_command="export",
            feed=str(self.feed),
            trace=False,
            akf=False,
            scitt=True,
            label="internal",
            model_id="",
            subject="",
            seed_hex="",
            out=str(self.dir / "scitt.json"),
            policy_bundle_hash="",
            data_class="",
            model_provider="",
            rekor_anchor="",
            key_id="",
        )
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_a_short_seed_is_refused(self):
        rc, _stdout, err = _run(self._args(seed_hex="ab" * 16))
        self.assertEqual(rc, 64)
        self.assertIn("64 hex chars", err)

    def test_a_non_hex_seed_is_refused(self):
        rc, _stdout, err = _run(self._args(seed_hex="zz"))
        self.assertEqual(rc, 64)
        self.assertIn("not valid hex", err)

    def test_a_missing_key_id_and_seed_is_refused(self):
        # `not key_id and seed is not None` -- with NO key id and NO
        # seed there is nothing to derive one from, so the command is
        # refused.  This is the half of the conjunction where the seed
        # is absent.
        rc, _stdout, err = _run(self._args())
        self.assertEqual(rc, 64)
        self.assertIn("--key-id", err)

    def test_a_given_key_id_is_used_as_is(self):
        # `args.key_id or ""` -- a GIVEN key id is used, not derived.
        # The bundle then names THAT key id in its protected header.
        out = self.dir / "scitt.json"
        rc, _stdout, err = _run(self._args(key_id="issuer-1", out=str(out)))
        self.assertEqual(rc, 0, err)
        bundle = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(bundle["statement"]["protected"]["4"], "issuer-1")

    def test_a_seed_derives_the_key_id(self):
        # `not key_id and seed is not None` -- with a seed and no key
        # id, the key id is DERIVED from the seed's pubkey.
        from ed25519 import public_key as ed_public_key

        seed = bytes(range(32))
        out = self.dir / "scitt.json"
        rc, _stdout, err = _run(self._args(seed_hex=seed.hex(), out=str(out)))
        self.assertEqual(rc, 0, err)
        bundle = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(
            bundle["statement"]["protected"]["4"], ed_public_key(seed).hex()
        )

    def test_a_missing_rekor_anchor_is_a_usage_error(self):
        rc, _stdout, err = _run(
            self._args(key_id="issuer-1", rekor_anchor=str(self.dir / "nope.json"))
        )
        self.assertEqual(rc, 64)
        self.assertIn("rekor-anchor", err)


if __name__ == "__main__":
    unittest.main()
