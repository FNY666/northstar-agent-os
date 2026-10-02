"""Operator CLI for the run-evidence component: seal and verify audit feeds.

Subcommands:

- ``seal``: read a canonical audit NDJSON feed (``audit.ndjson/1``, as produced
  by ``northstar-agent-runtime.audit_export``), append it to an evidence store
  file, and print the sealed manifest as JSON.
- ``verify``: re-open a store (fail-closed on tamper) and check that a sealed
  manifest genuinely describes it.

The ``--key-file`` holds the raw bytes of an HMAC secret. This is *local,
test-grade* sealing: it proves the file was not modified after sealing by
anyone without the secret, but a shared-secret MAC is not non-repudiation and
must never be presented as a production authenticity story. Production
deployments seal through their own signer infrastructure, not this CLI.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_adapter import parse_audit_feed, seal_audit_feed, verify_audit_seal
from evidence_contract import _identifier
from evidence_store import HmacTestSigner


def _read_key(key_file: str, key_id: str) -> HmacTestSigner:
    raw = Path(key_file).read_bytes()
    if len(raw) < 16:
        raise ValueError(f"key file {key_file!r} holds fewer than 16 bytes")
    return HmacTestSigner(key_id, raw)


def cmd_seal(args: argparse.Namespace) -> int:
    signer = _read_key(args.key_file, args.key_id)
    feed_text = Path(args.audit_feed).read_text(encoding="utf-8")
    records = parse_audit_feed(feed_text)
    manifest = seal_audit_feed(
        records,
        store_path=args.store,
        run_id=args.run_id,
        signer=signer,
        sealed_at=args.sealed_at,
    )
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.manifest_out:
        Path(args.manifest_out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    signer = _read_key(args.key_file, args.key_id)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    result = verify_audit_seal(
        args.store, args.run_id, manifest, {signer.key_id: signer.verifier()}
    )
    sys.stdout.write(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence",
        description="Seal and verify audit feeds with the run-evidence store.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("seal", help="append an audit feed to a store and seal it")
    seal.add_argument("--audit-feed", required=True, help="audit.ndjson/1 feed file")
    seal.add_argument("--store", required=True, help="evidence store file to create/extend")
    seal.add_argument("--run-id", required=True, help="run identifier for the store")
    seal.add_argument("--key-file", required=True, help="file holding the HMAC secret bytes")
    seal.add_argument("--key-id", required=True, help="key identifier recorded in the manifest")
    seal.add_argument("--sealed-at", type=int, default=None, help="Unix epoch for the seal (default: now)")
    seal.add_argument("--manifest-out", default=None, help="write manifest JSON here instead of stdout")
    seal.set_defaults(func=cmd_seal)

    verify = sub.add_parser("verify", help="verify a sealed manifest against a store")
    verify.add_argument("--store", required=True, help="evidence store file")
    verify.add_argument("--run-id", required=True, help="run identifier for the store")
    verify.add_argument("--manifest", required=True, help="sealed manifest JSON file")
    verify.add_argument("--key-file", required=True, help="file holding the HMAC secret bytes")
    verify.add_argument("--key-id", required=True, help="key identifier to resolve")
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _identifier(args.run_id, "run_id")
        _identifier(args.key_id, "key_id")
        return args.func(args)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        sys.stderr.write(f"evidence: error: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
