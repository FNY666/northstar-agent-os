"""Operator CLI for the run-evidence component: inspect, pack, seal, and verify.

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


def _read_bundle_manifest(bundle: str) -> dict[str, object]:
    path = Path(bundle)
    manifest_path = path / "manifest.json" if path.is_dir() else path
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest must be a JSON object")
    return value


def _bundle_paths(bundle: str) -> tuple[Path, Path, str]:
    root = Path(bundle)
    manifest_path = root if root.is_file() else root / "manifest.json"
    ledger_path = root / "ledger.jsonl" if root.is_dir() else root.with_name("ledger.jsonl")
    manifest = _read_bundle_manifest(str(manifest_path))
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("manifest is missing a non-empty run_id")
    return manifest_path, ledger_path, run_id


def _inspect_bundle(bundle: str) -> dict[str, object]:
    from evidence_store import EvidenceStore

    manifest_path, ledger_path, run_id = _bundle_paths(bundle)
    manifest = _read_bundle_manifest(str(manifest_path))
    store = EvidenceStore(ledger_path, run_id)
    verification = store.verify()
    counts: dict[str, int] = {}
    for entry in store.entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    claimed = manifest.get("ledger")
    claimed_count = claimed.get("entry_count") if isinstance(claimed, dict) else None
    claimed_head = claimed.get("head_digest") if isinstance(claimed, dict) else None
    matches = claimed_count == store.entry_count and claimed_head == store.head_digest
    return {
        "ok": verification.ok and matches,
        "bundle": str(manifest_path.parent),
        "run_id": run_id,
        "manifest": manifest,
        "ledger": verification.to_dict(),
        "manifest_matches_ledger": matches,
        "entry_kinds": dict(sorted(counts.items())),
    }


def _pack_bundle(source: str, output: str) -> dict[str, object]:
    """Copy one existing runtime bundle to a new output without following symlinks."""
    import os
    import shutil

    src = Path(source).resolve()
    dst = Path(output).resolve()
    if src == dst:
        raise ValueError("source and output must be different directories")
    if dst.exists():
        raise ValueError("output already exists; refusing to overwrite a bundle")
    if not (src / "ledger.jsonl").is_file() or not (src / "manifest.json").is_file():
        raise ValueError("source must contain ledger.jsonl and manifest.json")
    dst.mkdir(parents=True, mode=0o700)
    try:
        for name in ("ledger.jsonl", "manifest.json", "audit.ndjson"):
            path = src / name
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"{name} must be a regular file")
                shutil.copyfile(path, dst / name)
                os.chmod(dst / name, 0o600)
    except Exception:
        shutil.rmtree(dst, ignore_errors=True)
        raise
    return {"ok": True, "output": str(dst), "source": str(src)}


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


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        result = _inspect_bundle(args.bundle)
    except ValueError as error:
        result = {
            "ok": False,
            "bundle": str(Path(args.bundle)),
            "errors": [str(error)],
        }
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["ok"] else 2


def cmd_pack(args: argparse.Namespace) -> int:
    result = _pack_bundle(args.evidence_dir, args.output)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


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

    inspect = sub.add_parser("inspect", help="inspect a runtime evidence bundle read-only")
    inspect.add_argument("bundle", help="bundle directory containing ledger.jsonl and manifest.json")
    inspect.add_argument("--json", action="store_true", help="emit machine-readable JSON (always on)")
    inspect.set_defaults(func=cmd_inspect)

    pack = sub.add_parser("pack", help="copy one runtime evidence bundle to a new directory")
    pack.add_argument("evidence_dir", help="source runtime evidence bundle")
    pack.add_argument("--output", required=True, help="new output directory (must not exist)")
    pack.set_defaults(func=cmd_pack)

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
        if hasattr(args, "run_id"):
            _identifier(args.run_id, "run_id")
        if hasattr(args, "key_id"):
            _identifier(args.key_id, "key_id")
        return args.func(args)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        sys.stderr.write(f"evidence: error: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
