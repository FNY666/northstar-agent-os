"""The ``audit`` command: verify (and anchor) tamper-evident audit feeds.

``northstar audit verify <feed.ndjson>`` recomputes the hash chain from the
genesis anchor and reports the first broken link, or labels a legacy feed
*unprotected* instead of crashing. Exit codes are part of the interface:

* 0 — chain intact (``OK``)
* 1 — chain broken: tampering, reorder or bad signature (``BROKEN``)
* 2 — no chain fields at all: legacy feed (``UNPROTECTED``)
* 3 — unreadable file or invalid envelope (``INVALID``)

Default ``verify`` also enforces **causal order** via HLC stamps
(``hlc.py``): for every adjacent parent→child pair that both carry a
parseable ``"hlc"`` stamp, the child's stamp must not precede the
parent's — a smaller child stamp is reported as a ``causality-inversion``
break (exit 1, also in ``--json`` as ``causality_violation``). The check is
structural and involves no wall clock, so feeds written before HLC keep
verifying: pairs where either record lacks a parseable stamp are skipped.

``northstar audit anchor <feed.ndjson> --out manifest.json`` writes the
minimal offline head anchor (whole-file sha256 + head chain hash + record
count). Keep the manifest where the feed operator cannot rewrite it (WORM
storage, a transparency log, an RFC 3161 timestamp over the manifest);
``audit verify --anchor manifest.json`` then also detects wholesale
rewrites and tail truncation, which the bare chain cannot.

``northstar audit anchor-external <feed.ndjson> --out anchor.json --seed-hex <hex>``
submits the feed's head hash to the Sigstore Rekor transparency log as a
DSSE entry and writes the anchor record. Needs network; any failure exits 4
with a clear message instead of pretending the feed is anchored.

``northstar audit verify`` gains ``--external-anchor anchor.json``
(``--rekor-url`` optional): besides the local chain it checks the anchor
pins the same head, the anchor's DSSE signature, and re-fetches the entry
from the public log. Exit 5 means the external anchor could not be
confirmed (mismatch, or the log was unreachable).

``northstar audit verify-archive <dir>`` verifies a WORM archive package
(``sessions export --archive``); ``--online`` also re-fetches the Rekor
entry when the package carries an external anchor.

``--strict`` is an opt-in stricter profile for ``verify``: on top of the
hash chain it also enforces timestamp monotonicity (a record may regress
at most ``--clock-skew`` seconds, default 300 = 5 minutes, behind the
previous record) and nonce deduplication for records that carry a
``nonce`` field (draft-sharif-agent-audit-trail §6.3). It changes what
counts as verified: a feed that passes the default ``verify`` can fail
``--strict`` — e.g. old feeds with clock-skewed records — and that is
expected. Default ``verify`` semantics never change.
``northstar audit export <feed.ndjson> --trace`` emits the feed's chain
head as a TRACE v0.2-shaped Trust Record (JCS JSON, to stdout or --out):
``tool_transcript.hash`` commits the head hash, ``references`` gains a
``behavior-trace`` pointer at the feed digest, ``policy.enforcement_mode``
is ``enforce``, and ``origin.kind=log-import`` /
``runtime.platform=software-only`` keep the record honest about having no
hardware attestation. ``--seed-hex`` adds an embedded Ed25519 signature
(plus ``cnf.jwk``); without it the record is unsigned. This is an
evidence-shape export, not a TRACE conformance claim: v0.2 is a Developer
Preview and software-only records are never attested evidence. Unchained
or broken feeds are refused loudly (exits 2/3).

``northstar audit keygen`` prints a fresh Ed25519 seed/public-key pair
(hex). The seed signs feeds offline; only the public key is needed to
verify. Key handling is the operator's job — this command just mints bits.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

USAGE_ERROR = 64
EXTERNAL_ANCHOR_FAILED = 4
EXTERNAL_UNVERIFIED = 5


def add_audit_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="audit_command")

    verifying = sub.add_parser(
        "verify",
        help="recompute an audit feed's hash chain from its genesis anchor",
        description=(
            "Offline, deterministic. Reports OK, BROKEN <line>, UNPROTECTED "
            "(legacy feed, no chain fields) or INVALID. Never modifies the feed."
        ),
    )
    verifying.add_argument("feed", help="audit NDJSON feed file to verify")
    verifying.add_argument("--pubkey", default="", help="hex Ed25519 public key to check record signatures against")
    verifying.add_argument(
        "--expect-session-id", default="", help="the genesis anchor must name this session id"
    )
    verifying.add_argument(
        "--expect-run-id", default="", help="the genesis anchor must name this run id"
    )
    verifying.add_argument(
        "--anchor",
        default="",
        help="head-anchor manifest JSON (from `audit anchor`); also checks for rewrites/truncation",
    )
    verifying.add_argument("--json", action="store_true", help="emit the result as one JSON object")
    verifying.add_argument(
        "--external-anchor",
        default="",
        help="Rekor anchor record JSON (from `audit anchor-external`); also checks the "
        "anchor pins this head, its DSSE signature, and the entry's presence in the "
        "public log (needs network)",
    )
    verifying.add_argument(
        "--rekor-url",
        default="",
        help="transparency log base URL (default: the public Sigstore Rekor)",
    )
    verifying.add_argument(
        "--strict",
        action="store_true",
        help="opt-in strict profile: on top of the chain also enforce timestamp "
        "monotonicity (regressions beyond --clock-skew fail, located at the "
        "offending record) and nonce deduplication. Changes what counts as "
        "verified: feeds passing the default verify can fail --strict.",
    )
    verifying.add_argument(
        "--clock-skew",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="under --strict, how far a record's timestamp may regress behind "
        "the previous record before failing (default 300 = 5 minutes)",
    )

    anchoring = sub.add_parser(
        "anchor",
        help="write the minimal offline head anchor for a feed file",
        description=(
            "Writes a JSON manifest pinning the feed's bytes, head chain hash "
            "and record count. Store it out of the feed operator's reach; "
            "`audit verify --anchor` enforces it. No network involved."
        ),
    )
    anchoring.add_argument("feed", help="audit NDJSON feed file to anchor")
    anchoring.add_argument("--out", required=True, help="where to write the manifest JSON")
    anchoring.add_argument("--anchored-at", default="", help="RFC 3339 timestamp to record in the manifest")

    keygen = sub.add_parser(
        "keygen",
        help="mint a fresh Ed25519 seed/public-key pair (hex) for feed signing",
        description="Prints seed_hex and pubkey_hex. Guard the seed; verifiers only need the public key.",
    )
    keygen.add_argument("--json", action="store_true", help="emit the key pair as one JSON object")

    anchoring_external = sub.add_parser(
        "anchor-external",
        help="anchor a feed's head hash in the Sigstore Rekor transparency log",
        description=(
            "Submits the head chain hash as a DSSE entry to Rekor and writes the "
            "anchor record. Needs network; any failure exits 4 with a clear "
            "message instead of pretending the feed is anchored."
        ),
    )
    anchoring_external.add_argument("feed", help="audit NDJSON feed file to anchor")
    anchoring_external.add_argument("--out", required=True, help="where to write the anchor record JSON")
    anchoring_external.add_argument(
        "--seed-hex", required=True, help="64-hex-char Ed25519 seed signing the anchor statement"
    )
    anchoring_external.add_argument(
        "--rekor-url", default="", help="transparency log base URL (default: the public Sigstore Rekor)"
    )

    verifying_archive = sub.add_parser(
        "verify-archive",
        help="verify a WORM archive package directory (sessions export --archive)",
        description=(
            "Offline: file hashes, feed chain, offline head anchor, and the "
            "external anchor's signature. --online additionally re-fetches the "
            "Rekor entry when the package carries an external anchor."
        ),
    )
    verifying_archive.add_argument("directory", help="archive package directory to verify")
    verifying_archive.add_argument("--online", action="store_true", help="also re-fetch the Rekor entry")
    verifying_archive.add_argument(
        "--rekor-url", default="", help="transparency log base URL (default: the public Sigstore Rekor)"
    )
    verifying_archive.add_argument("--json", action="store_true", help="emit the result as one JSON object")

    exporting = sub.add_parser(
        "export",
        help="export a feed's chain head as a TRACE v0.2-shaped Trust Record",
        description=(
            "Offline, deterministic, pure software: reads a chained audit feed and "
            "emits one export record. Two shapes: --trace emits a TRACE v0.2-shaped "
            "Trust Record (JCS JSON) committing the chain head by hash "
            "(tool_transcript.hash), with a behavior-trace reference to the feed "
            "digest, policy.enforcement_mode=enforce, and origin.kind=log-import / "
            "runtime.platform=software-only. This is an evidence-shape export, not a "
            "TRACE conformance claim: v0.2 is a Developer Preview and software-only "
            "records are never attested evidence. --scitt emits the SCITT "
            "(RFC 9943) / COSE Receipts (RFC 9942) spike bundle: a JSON-diagnostic "
            "model of a Signed Statement about the feed's anchor manifest, "
            "optionally transparent (a receipt shape mapped from a Rekor anchor "
            "record under unprotected label 394). The spike is a shape model, "
            "never a conformant SCITT message. Both shapes fail loudly on "
            "unchained or broken feeds."
        ),
    )
    exporting.add_argument("feed", help="chained audit NDJSON feed file to export")
    exporting.add_argument(
        "--trace",
        action="store_true",
        help="emit the TRACE v0.2 Trust Record shape",
    )
    exporting.add_argument(
        "--akf",
        action="store_true",
        help="emit an AKF v1.1 unit assembled from the feed (spike: log-import, "
        "not an AKF conformance claim; exactly one of --trace/--akf is required)",
    )
    exporting.add_argument(
        "--label",
        default="internal",
        choices=("public", "internal", "confidential", "highly-confidential", "restricted"),
        help="AKF classification label for --akf (default: internal; the feed's own "
        "data classes are not mapped, so a default is honest rather than guessed)",
    )
    exporting.add_argument(
        "--scitt",
        action="store_true",
        help="emit the SCITT (RFC 9943) / COSE Receipts (RFC 9942) spike bundle shape",
    )
    exporting.add_argument(
        "--rekor-anchor",
        default="",
        help="with --scitt: path to a Rekor anchor record JSON (from "
        "`audit anchor-external`); mapped to a receipt shape and embedded "
        "under unprotected label 394, forming the Transparent Statement shape",
    )
    exporting.add_argument(
        "--key-id",
        default="",
        help="with --scitt: issuer key id for the protected header (kid, "
        "label 4); defaults to the signing key's pubkey hex when --seed-hex "
        "is given",
    )
    exporting.add_argument("--out", default="", help="write the record to this file instead of stdout")
    exporting.add_argument(
        "--seed-hex",
        default="",
        help="64-hex-char Ed25519 seed: sign the record (embedded profile) and add cnf.jwk; "
        "without it the record is unsigned",
    )
    exporting.add_argument(
        "--subject", default="", help="record subject (default: did:northstar:run/<run-id> or session)"
    )
    exporting.add_argument(
        "--policy-bundle-hash",
        default="",
        help="policy bundle hash as 'sha256:<hex>' (omitted when unknown)",
    )
    exporting.add_argument(
        "--data-class",
        default="",
        choices=("", "public", "internal", "confidential", "restricted"),
        help="highest data class touched (omitted when unknown)",
    )
    exporting.add_argument("--model-provider", default="", help="model provider name (omitted when unknown)")
    exporting.add_argument("--model-id", default="", help="model id (omitted when unknown)")



def _load_pubkey(hexkey: str) -> bytes:
    try:
        raw = bytes.fromhex(hexkey)
    except ValueError:
        raise ValueError("not valid hex") from None
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return raw


def run_audit(args: argparse.Namespace) -> int:
    from audit_chain import anchor_manifest, check_anchor, generate_keypair, verify_file

    command = getattr(args, "audit_command", None)
    if command == "keygen":
        seed, pubkey = generate_keypair()
        if getattr(args, "json", False):
            print(json.dumps({"seed_hex": seed.hex(), "pubkey_hex": pubkey.hex()}))
        else:
            print(f"seed_hex:   {seed.hex()}")
            print(f"pubkey_hex: {pubkey.hex()}")
            print("guard the seed; verifiers only need pubkey_hex", file=sys.stderr)
        return 0
    if command == "anchor":
        feed = Path(args.feed)
        if not feed.is_file():
            print(f"audit: no such feed file: {feed}", file=sys.stderr)
            return USAGE_ERROR
        try:
            manifest = anchor_manifest(feed, anchored_at=args.anchored_at or None)
        except (OSError, UnicodeDecodeError, ValueError) as error:
            print(f"audit: cannot anchor {feed}: {error}", file=sys.stderr)
            return 3
        out = Path(args.out)
        out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"audit: anchored {manifest['records']} records, head {str(manifest['head_chain_hash'])[:16]}… -> {out}")
        return 0
    if command == "verify":
        pubkey = None
        if args.pubkey:
            try:
                pubkey = _load_pubkey(args.pubkey)
            except ValueError as error:
                print(f"audit: bad --pubkey: {error}", file=sys.stderr)
                return USAGE_ERROR
        if args.clock_skew < 0:
            print("audit: --clock-skew must be >= 0", file=sys.stderr)
            return USAGE_ERROR
        result = verify_file(
            args.feed,
            public_key=pubkey,
            expect_session_id=args.expect_session_id or None,
            expect_run_id=args.expect_run_id or None,
            strict=bool(args.strict),
            clock_skew_seconds=args.clock_skew,
        )
        anchor_note = ""
        anchor_failed = False
        if args.anchor and result.ok:
            try:
                manifest = json.loads(Path(args.anchor).read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                print(f"audit: cannot read anchor manifest: {error}", file=sys.stderr)
                return USAGE_ERROR
            anchor_ok, anchor_note = check_anchor(args.feed, manifest)
            result.anchor_ok = anchor_ok
            if not anchor_ok:
                # The feed differs from the anchored snapshot: wholesale
                # rewrite or tail truncation. The bare chain cannot see this;
                # the anchor can, so it reports as BROKEN, not INVALID.
                result.ok = False
                result.reason = anchor_note
                anchor_failed = True
        external_note = ""
        external_state = "not-checked"
        if args.external_anchor and result.ok:
            from audit_chain import anchor_manifest as _head_of
            from audit_rekor import (
                RekorError,
                verify_anchor_in_log,
                verify_anchor_offline,
            )

            try:
                external_record = json.loads(Path(args.external_anchor).read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                print(f"audit: cannot read external anchor record: {error}", file=sys.stderr)
                return USAGE_ERROR
            head_now = _head_of(args.feed).get("head_chain_hash")
            ok, external_note = verify_anchor_offline(external_record, head_chain_hash=head_now)
            if ok:
                try:
                    ok, external_note = verify_anchor_in_log(
                        external_record,
                        rekor_url=args.rekor_url or None,
                    )
                    external_state = "ok" if ok else "mismatch"
                except RekorError as error:
                    # The log is unreachable: existence is unverified. This is
                    # reported distinctly (exit 5), never silently passed.
                    print(f"audit: cannot reach transparency log: {error}", file=sys.stderr)
                    return EXTERNAL_UNVERIFIED
            else:
                external_state = "mismatch"
            if not ok:
                result.ok = False
                result.reason = f"external anchor: {external_note}"
                anchor_failed = True
        if result.ok:
            status = "OK"
        elif result.unprotected:
            status = "UNPROTECTED"
        elif anchor_failed or result.broken_at is not None:
            status = "BROKEN"
        else:
            status = "INVALID"
        if getattr(args, "json", False):
            print(json.dumps({
                "status": status,
                "ok": result.ok,
                "broken_at": result.broken_at,
                "records": result.records,
                "chained": result.chained,
                "unprotected": result.unprotected,
                "reason": result.reason,
                "signature_failures": result.signature_failures,
                "anchor_ok": result.anchor_ok,
                "external_anchor": {"state": external_state, "note": external_note},
                "strict": bool(getattr(args, "strict", False)),
                "strict_violation": result.strict_violation,
                "causality_violation": result.causality_violation,
            }))
        else:
            detail = f" ({result.reason})" if result.reason else ""
            extra = ""
            if result.broken_at is not None:
                extra = f" at line {result.broken_at}"
            anchor_extra = f"; anchor: {anchor_note}" if args.anchor and result.anchor_ok is not None else ""
            external_extra = (
                f"; external anchor: {external_state} ({external_note})"
                if args.external_anchor
                else ""
            )
            print(f"audit verify: {status}{extra} — {result.records} records, {result.chained} chained{detail}{anchor_extra}{external_extra}")
        if result.ok:
            return 0
        if result.unprotected:
            return 2
        if status == "INVALID":
            return 3
        return 1
    if command == "anchor-external":
        from audit_rekor import REKOR_V1_DEFAULT, RekorError, anchor_feed_head

        feed = Path(args.feed)
        if not feed.is_file():
            print(f"audit: no such feed file: {feed}", file=sys.stderr)
            return USAGE_ERROR
        try:
            seed = bytes.fromhex(args.seed_hex)
        except ValueError:
            print("audit: --seed-hex is not valid hex", file=sys.stderr)
            return USAGE_ERROR
        if len(seed) != 32:
            print("audit: --seed-hex must be 64 hex chars (32 bytes)", file=sys.stderr)
            return USAGE_ERROR
        try:
            record = anchor_feed_head(
                feed, seed, rekor_url=args.rekor_url or REKOR_V1_DEFAULT
            )
        except (RekorError, ValueError, OSError) as error:
            # Network/log failure is never silent: the feed is NOT anchored.
            print(f"audit: external anchoring failed: {error}", file=sys.stderr)
            return EXTERNAL_ANCHOR_FAILED
        out = Path(args.out)
        out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"audit: anchored head {record['payload']['head_chain_hash'][:16]}… "
            f"at log index {record['log_index']} -> {out}"
        )
        return 0
    if command == "verify-archive":
        from audit_archive import verify_archive

        result = verify_archive(
            args.directory,
            rekor_url=args.rekor_url or None,
            online=bool(getattr(args, "online", False)),
        )
        status = "OK" if result.ok else "BROKEN"
        if getattr(args, "json", False):
            print(json.dumps({
                "status": status,
                "ok": result.ok,
                "reason": result.reason,
                "files": result.files,
                "records": result.records,
                "head_chain_hash": result.head_chain_hash,
                "retain_until": result.retain_until,
                "external_anchor": result.external_anchor,
            }))
        else:
            extra = f" — {result.reason}" if result.reason else ""
            print(
                f"audit verify-archive: {status} — {result.files} files, "
                f"{result.records} records{extra}"
            )
        return 0 if result.ok else 1
    if command == "export":
        want_trace = getattr(args, "trace", False)
        want_akf = getattr(args, "akf", False)
        want_scitt = getattr(args, "scitt", False)
        shapes = [bool(want_trace), bool(want_akf), bool(want_scitt)]
        if sum(shapes) != 1:
            print(
                "audit export: pass exactly one of --trace, --akf or --scitt",
                file=sys.stderr,
            )
            return USAGE_ERROR
        if want_akf:
            return _run_akf_export(args)
        if want_scitt:
            return _run_audit_scitt_export(args)
        return _run_audit_export(args)
    print(
        "audit: pass a subcommand: verify, anchor, anchor-external, verify-archive, export or keygen "
        "(--help for flags)",
        file=sys.stderr,
    )
    return USAGE_ERROR


def _run_akf_export(args: argparse.Namespace) -> int:
    """``audit export <feed> --akf``: AKF v1.1 unit export (spike, offline)."""
    from akf_export import (
        AKF_SHAPE_LABEL,
        build_akf_unit,
        unit_to_json_bytes,
        validate_akf_unit,
    )

    feed = Path(args.feed)
    if not feed.is_file():
        print(f"audit: no such feed file: {feed}", file=sys.stderr)
        return USAGE_ERROR
    try:
        unit = build_akf_unit(
            feed,
            label=args.label,
            subject=args.subject or None,
            model_id=args.model_id or None,
        )
    except ValueError as error:
        message = str(error)
        print(f"audit: cannot export --akf: {message}", file=sys.stderr)
        # Mirror verify's exit vocabulary: unprotected vs broken feeds.
        if "UNPROTECTED" in message:
            return 2
        return 3
    problems = validate_akf_unit(unit)
    if problems:
        print(
            f"audit: --akf self-check failed: {'; '.join(problems)}",
            file=sys.stderr,
        )
        return 3
    out_bytes = unit_to_json_bytes(unit) + b"\n"
    if args.out:
        out_path = Path(args.out)
        try:
            out_path.write_bytes(out_bytes)
        except OSError as error:
            print(f"audit: cannot write {out_path}: {error}", file=sys.stderr)
            return 3
        where = str(out_path)
    else:
        sys.stdout.buffer.write(out_bytes)
        where = "stdout"
    print(
        f"audit: exported {AKF_SHAPE_LABEL} "
        f"({len(unit['claims'])} claims; unsigned spike; run `akf audit` for the real check) "
        f"-> {where}",
        file=sys.stderr,
    )
    return 0


def _run_audit_export(args: argparse.Namespace) -> int:
    """``audit export <feed> --trace``: Trust Record shape export (offline)."""
    from trace_export import TRACE_SHAPE_LABEL, build_trace_record, record_to_json_bytes

    feed = Path(args.feed)
    if not feed.is_file():
        print(f"audit: no such feed file: {feed}", file=sys.stderr)
        return USAGE_ERROR
    try:
        seed = bytes.fromhex(args.seed_hex) if args.seed_hex else None
    except ValueError:
        print("audit: --seed-hex is not valid hex", file=sys.stderr)
        return USAGE_ERROR
    if seed is not None and len(seed) != 32:
        print("audit: --seed-hex must be 64 hex chars (32 bytes)", file=sys.stderr)
        return USAGE_ERROR
    try:
        record = build_trace_record(
            feed,
            policy_bundle_hash=args.policy_bundle_hash or None,
            data_class=args.data_class or None,
            subject=args.subject or None,
            model_provider=args.model_provider or None,
            model_id=args.model_id or None,
            seed=seed,
        )
    except ValueError as error:
        message = str(error)
        print(f"audit: cannot export --trace: {message}", file=sys.stderr)
        # Mirror verify's exit vocabulary: unprotected vs broken feeds.
        if "UNPROTECTED" in message:
            return 2
        return 3
    out_bytes = record_to_json_bytes(record) + b"\n"
    if args.out:
        out_path = Path(args.out)
        try:
            out_path.write_bytes(out_bytes)
        except OSError as error:
            print(f"audit: cannot write {out_path}: {error}", file=sys.stderr)
            return 3
        where = str(out_path)
    else:
        sys.stdout.buffer.write(out_bytes)
        where = "stdout"
    signed_note = "signed" if seed is not None else "unsigned (shape only, no conformance claim)"
    print(
        f"audit: exported {TRACE_SHAPE_LABEL} [{signed_note}] -> {where}",
        file=sys.stderr,
    )
    return 0


def _run_audit_scitt_export(args: argparse.Namespace) -> int:
    """``audit export <feed> --scitt``: SCITT/RFC 9943 spike bundle (offline)."""
    from audit_scitt import SCITT_SPIKE_LABEL, build_scitt_bundle, bundle_to_json_bytes

    feed = Path(args.feed)
    if not feed.is_file():
        print(f"audit: no such feed file: {feed}", file=sys.stderr)
        return USAGE_ERROR
    try:
        seed = bytes.fromhex(args.seed_hex) if args.seed_hex else None
    except ValueError:
        print("audit: --seed-hex is not valid hex", file=sys.stderr)
        return USAGE_ERROR
    if seed is not None and len(seed) != 32:
        print("audit: --seed-hex must be 64 hex chars (32 bytes)", file=sys.stderr)
        return USAGE_ERROR
    key_id = args.key_id or ""
    if not key_id and seed is not None:
        from ed25519 import public_key as ed_public_key

        key_id = ed_public_key(seed).hex()
    if not key_id:
        print(
            "audit: --scitt needs --key-id (issuer identity for the protected "
            "header; defaults to the signing key's pubkey hex with --seed-hex)",
            file=sys.stderr,
        )
        return USAGE_ERROR
    rekor_anchor = None
    if args.rekor_anchor:
        anchor_path = Path(args.rekor_anchor)
        try:
            rekor_anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"audit: cannot read --rekor-anchor {anchor_path}: {error}", file=sys.stderr)
            return USAGE_ERROR
        if not isinstance(rekor_anchor, dict):
            print("audit: --rekor-anchor must be a JSON object (anchor record)", file=sys.stderr)
            return USAGE_ERROR
    try:
        bundle = build_scitt_bundle(
            feed, key_id=key_id, seed=seed, rekor_anchor=rekor_anchor
        )
    except ValueError as error:
        message = str(error)
        print(f"audit: cannot export --scitt: {message}", file=sys.stderr)
        # Mirror the --trace exit vocabulary: unprotected vs broken feeds.
        if "no chained head" in message:
            return 2
        return 3
    out_bytes = bundle_to_json_bytes(bundle) + b"\n"
    if args.out:
        out_path = Path(args.out)
        try:
            out_path.write_bytes(out_bytes)
        except OSError as error:
            print(f"audit: cannot write {out_path}: {error}", file=sys.stderr)
            return 3
        where = str(out_path)
    else:
        sys.stdout.buffer.write(out_bytes)
        where = "stdout"
    shape = "transparent-statement" if rekor_anchor is not None else "signed-statement"
    signed_note = "signed (JSON-level)" if seed is not None else "unsigned (shape only)"
    print(
        f"audit: exported {SCITT_SPIKE_LABEL} [{shape}, {signed_note}] -> {where}",
        file=sys.stderr,
    )
    return 0
