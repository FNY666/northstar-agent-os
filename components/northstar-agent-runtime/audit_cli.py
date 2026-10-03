"""The ``audit`` command: verify (and anchor) tamper-evident audit feeds.

``northstar audit verify <feed.ndjson>`` recomputes the hash chain from the
genesis anchor and reports the first broken link, or labels a legacy feed
*unprotected* instead of crashing. Exit codes are part of the interface:

* 0 — chain intact (``OK``)
* 1 — chain broken: tampering, reorder or bad signature (``BROKEN``)
* 2 — no chain fields at all: legacy feed (``UNPROTECTED``)
* 3 — unreadable file or invalid envelope (``INVALID``)

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
        result = verify_file(
            args.feed,
            public_key=pubkey,
            expect_session_id=args.expect_session_id or None,
            expect_run_id=args.expect_run_id or None,
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
    print(
        "audit: pass a subcommand: verify, anchor, anchor-external, verify-archive or keygen "
        "(--help for flags)",
        file=sys.stderr,
    )
    return USAGE_ERROR
