# Examples

Self-contained recipes on top of the Northstar components. Every example runs
**offline** (scripted model turns — no API key, no network) unless its own
README says otherwise, and each one is a template to copy rather than a part
of the product.

| Example | What it demonstrates | Run it |
| --- | --- | --- |
| [demo](demo/README.md) | one full governed agent loop — Read tool call + scripted turn through the same code path as a live run (permission gate, ceilings, event stream, append-only transcript) | `cd demo && sh run_offline.sh` |
| [remote-canary](remote-canary/README.md) | operator-run channel canary for a hosted worker — SSH-forward the sidecar socket and probe it end to end (needs a real worker host; never run by CI) | `NS_WORKER=user@host sh examples/remote-canary/run_remote_canary.sh` |
| [session-panel](session-panel/README.md) | offline viewer for session transcripts and audit exports — one self-contained HTML file, drag-and-drop, no server and no network (fingerprint + stats + timeline) | open `examples/session-panel/session-panel.html` in a browser |
| [observability](observability/README.md) | local trace backend for the runtime — Jaeger + Grafana over docker compose, with the `otel_bootstrap.py` provider seam; model turns stay scripted/offline; needs Docker + one pip extra | `docker compose -f examples/observability/docker-compose.yml up -d` |
| [sdk](sdk/README.md) | embed one governed run in your own Python via `sdk.run()` — no subprocess, no API key; same gate refuses an unallowed Write | `python3 examples/sdk/run_sdk_demo.py` |
| [ci-readonly-review](ci-readonly-review/README.md) | consumer CI recipe: governed, read-only agent review of a pull request, capped and audited; a template for *your* pipeline, not wired into this repository's CI | copy `run_review.sh` into your repo and read its comments |

Picking the right starting point:

- New to the runtime? Start with [demo](demo/README.md) — it is the shortest
  path to a real governed run and exits 0 only when everything worked.
- Embedding the loop in your own Python program (not shelling out to the CLI)?
  Start with [sdk](sdk/README.md) — `sdk.run()` returns a `RunReport` with the
  same governance the CLI applies.
- Wiring a governed review into your own CI? Start with
  [ci-readonly-review](ci-readonly-review/README.md) and read the
  [governed-run-cookbook](../docs/guides/governed-run-cookbook.md) for the
  switches it uses (`--read-only`, ceilings, transcripts).
- Extending the stack? Each example keeps to public CLI surface, so it keeps
  working as the components evolve; the repository's own CI smoke runs the
  demo script on every push (see [packaging-and-ci](../docs/guides/packaging-and-ci.md)).

Structure expectation (enforced by `tests/test_docbuild.py`): every directory
under `examples/` with a `README.md` must be listed on this page.
