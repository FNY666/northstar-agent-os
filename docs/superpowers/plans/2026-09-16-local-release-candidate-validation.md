# Local release candidate validation

## Candidate

The local candidate is `2ce0e84`, the first complete non-authorizing
continuation core: host-owned checkpoint contract, drift verification, explicit
AgentRuntime adapter, durable checkpoint store, and runtime persistence adapter.

## Independent validation

- Build a git bundle from the candidate HEAD.
- Clone the bundle into a fresh temporary directory.
- Run checkpoint/store focused tests: 22/22.
- Run the complete runtime suite: 426/426.
- Run the complete interop suite: 620/620.
- Confirm the fresh clone HEAD equals `2ce0e84`.

## Result

`RC_VERIFICATION=PASS`. This validates the local artifact and its tests; it is
not a production release, remote push, or proof that future execution admission
is safe. The candidate remains local-only and the remote remains frozen at
`c371a15`.

## Required discussion before release

1. Whether this non-authorizing continuation core is the intended local release
   candidate.
2. Whether and when to align with the parallel session before any push.
3. Whether the next generation should add execution admission or integrate the
   completion contract first, while preserving the non-authorizing boundary.
