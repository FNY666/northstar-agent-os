"""Deterministic channel probe for a remote sidecar socket (T5 canary part 1).

Two modes:

* ``--probe`` (default): one JSON-lines round trip against the (forwarded)
  sidecar socket, using a request that is *shaped but invalid* (timeout_ms
  outside the permitted range). The real server rejects it in
  ``sidecar.run_one`` **before any codex process is started**, so this mode
  needs no model, no API key and no codex binary on the worker - it proves
  the channel: socket reachable, framing intact, request_id echoed, bounded
  response. Pass = deterministic, repeatable, safe to run any time.
* ``--real``: sends a valid, tiny request that does launch codex on the
  worker. Needs codex + credentials there. Success means the full path
  works; codex_error/timeout are reported as inconclusive (exit 2), not as
  a channel failure.

Exit codes: 0 pass, 1 channel/probe failure, 2 inconclusive (--real only).
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

PROBE_TIMEOUT_MS = 999_999_999  # outside contract [MIN_TIMEOUT_MS, MAX_TIMEOUT_MS]
REAL_TIMEOUT_MS = 120_000  # inside the permitted range; launch codex on the worker


def probe_once(socket_path: str, request: dict[str, Any]) -> dict[str, Any]:
    """One connection, one JSON-lines request, one response (as the runtime does)."""
    deadline = time.monotonic() + 15.0
    path = Path(socket_path)
    while not path.exists():
        if time.monotonic() > deadline:
            raise ConnectionError(f"sidecar socket not found at {socket_path}")
        time.sleep(0.1)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(15.0)
    try:
        conn.connect(str(path))
        conn.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        raw = b"".join(chunks).decode("utf-8", "replace").strip()
        if not raw:
            raise ConnectionError("sidecar closed without a response line")
        return json.loads(raw)
    finally:
        conn.close()


def _probe_request() -> dict[str, Any]:
    return {
        "request_id": f"canary-probe-{int(time.time())}",
        "prompt": "channel probe: this prompt must never reach a model",
        "timeout_ms": PROBE_TIMEOUT_MS,
    }


def _real_request() -> dict[str, Any]:
    return {
        "request_id": f"canary-real-{int(time.time())}",
        "prompt": "Reply with exactly: canary-ok",
        "timeout_ms": REAL_TIMEOUT_MS,
    }


def run_probe(socket_path: str, *, real: bool = False) -> int:
    request = _real_request() if real else _probe_request()
    response = probe_once(socket_path, request)
    rid = response.get("request_id")
    status = response.get("status")
    print(f"request_id : {rid}")
    print(f"status     : {status}")
    if rid != request["request_id"]:
        print("FAIL: request_id was not echoed", file=sys.stderr)
        return 1
    if not real:
        ok = status == "rejected" and any(
            "timeout_ms" in str(error) for error in response.get("errors", [])
        )
        if not ok:
            print(f"FAIL: expected a bounded rejection, got {json.dumps(response)}", file=sys.stderr)
            return 1
        print("PASS: JSON-lines round trip over the sidecar socket works")
        return 0
    # --real: codex actually ran on the worker.
    if status == "ok":
        print("PASS: real run completed over the channel")
        return 0
    if status in ("codex_error", "timeout", "internal_error", "protocol_error"):
        error = response.get("error") or response.get("errors") or status
        print(f"INCONCLUSIVE: sidecar answered but the run did not succeed: {error}")
        return 2
    print(f"FAIL: unexpected status {status!r}: {json.dumps(response)}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="local (forwarded) sidecar socket path")
    parser.add_argument("--real", action="store_true", help="launch a real run on the worker")
    args = parser.parse_args(argv)
    try:
        return run_probe(args.socket, real=args.real)
    except (ConnectionError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
