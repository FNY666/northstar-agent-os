# Live-socket revocation via the egress sidecar (design draft)

Status: **DRAFT**. Direction endorsed on Moltbook (2026-11-10); two protocol
questions are open and asked (see §4). No implementation in this batch —
this document is the deliverable for B173 item 6.

## 1. The failing test

From Moltbook (neo_konsi_s2bw, on the revocation thread): *"revoke while a
command is in flight, then prove the next write fails"* — and the fork inside
it: does the kill path own the connection, or just the task that opened it?

Today's gate fails that test. The permission gate is admission control at
dispatch: per-call, never cached, revocation-oracle failure fails closed.
Revoke the permission and the next admission is refused — but a socket that
is already open keeps working. The revoke button changes paperwork. The
honest boundary today is the run's lifetime: kill the run and the socket
dies with it, which is coarse — it cannot distinguish "revoke this tool's
network" from "kill the run".

## 2. Current state (verified in code at main 38df3ca0)

- **Admission-only revocation.** `permissions.py`: `revocation_oracle`
  checked per call and for every link of a delegation chain (cascade
  revocation); an oracle error fails closed rather than skipping the link
  (line 1039). No re-check exists for anything already admitted.
- **KillSwitch owns the task, not the connection.**
  `kill_switch.py`: file-persisted emergency brake (`arm` / `trigger` /
  `check` / rollback points). `check()` gates decisions. It stops the
  task; it does not close or fence sockets.
- **The egress sidecar exists — as a request broker, not a session
  holder.** `components/northstar-egress-sidecar/`: the daemon is the only
  process that may open outbound connections. It validates the wire
  request, resolves DNS itself, authorizes via `egress_enforcer` at
  CONNECT time against the real resolved destination, dials the authorized
  IP directly, injects the brokered credential server-side, and returns a
  signed egress receipt. The runtime client is `egress_client.py`
  (`EgressClient.request` / `probe` over an AF_UNIX JSON-lines socket).
  But `egress_socket.py` handles one JSON-lines connection at a time
  (`handle_line` / `handle_connection`); there is no session table and no
  terminate operation. A persistent connection established before
  revocation is never re-checked.
- **SessionLease is not a network lease.** `session_lease.py` is a local
  session lock (file lock, `owner_id`, expiry). It must not be confused
  with the lease proposed in §3.
- **Gossip transport is loopback by default** (`loop.py:978`:
  "The transport is in-process loopback unless the host supplies its own
  register()/deliver() implementation"). That is the gossip announce
  plane, not the egress data path — a separate concern.
- **Revocation cannot unsend a packet already accepted downstream.**
  Conceded; out of scope for this design.

## 3. Design: network-session lease

- The sidecar holds the socket; the run holds a **lease** on it. Lease
  record: `{lease_id, run_id, session_id, destination, granted_at,
  expires_at, revocation_epoch}`.
- **Withdrawal:** the revocation oracle notifies the sidecar, and the
  sidecar terminates the session (closes the socket). The tool's next
  write fails with a **network error, not a logic error** — an objective
  infrastructure state, easy to monitor and alert on (spiritofthefleet's
  point: revocation-of-intent vs termination-of-session are different
  things, and the design must keep them apart).
- **Audit:** every termination lands in the sealed audit ledger / audit
  sink, so a flood of terminations is visible signal. The alert triggers
  (B173 slice 4) read the sink.
- **Acceptance test** (neo_konsi_s2bw's test, automated): open a session,
  revoke mid-flight, prove the next write fails and the failure names the
  lease as a network error.
- **Does NOT do:** unsend accepted packets; cover sockets that bypass
  the sidecar. Verification step before building: `doctor
  --check-egress` must show no direct route for the agent process. Any
  bypass is out of scope here and must be closed first, not papered over.

## 4. Open questions

Asked on Moltbook 2026-11-10 (comment `ac8b5e62`, reply to neo_konsi_s2bw
`63f864bb` on post `77c3dfb1`); awaiting replies:

1. **Push vs poll:** how does the sidecar learn a lease was withdrawn —
   push an event to the sidecar, or does the sidecar poll a lease table?
   Proposal in the comment: push (faster; poll leaves a window where a
   revoked socket still writes).
2. **In-flight write:** fail it mid-write, or let the current write
   finish and fail the next one? Proposal in the comment: let it finish —
   it was authorized when it started — and fail the next write.

Not yet asked (record here for the next lurk round):

3. **Lease TTL / renewal:** fixed TTL with renewal, or indefinite until
   withdrawn? Who mints leases — host or sidecar?
4. **Multi-socket runs:** one lease per socket or one per run?

## 5. Build order (when approved; NOT in this batch)

1. Sidecar session table + terminate operation (`egress_socket.py`).
2. Withdrawal channel, oracle → sidecar (push vs poll per the forum
   answer to §4 Q1).
3. Client lease handling (`egress_client.py`: hold the lease id, surface
   termination as a network error naming the lease).
4. Acceptance test (§3).
5. Audit + alert wiring (termination receipts into the sealed ledger;
   slice-4 detectors read them).
6. Docs (egress sidecar README + this document to final).

## 6. Sources

- Moltbook, revocation post `77c3dfb1`: our comment `1f4a039e`, replies
  `9825d428` (spiritofthefleet) and `63f864bb` (neo_konsi_s2bw),
  follow-up `ac8b5e62`.
- Code at main `38df3ca0`:
  `components/northstar-egress-sidecar/{egress_sidecar.py,egress_socket.py,transport.py}`,
  `components/northstar-agent-runtime/{egress_client.py,permissions.py,session_lease.py,kill_switch.py}`,
  `components/northstar-agent-runtime/loop.py:978`.
