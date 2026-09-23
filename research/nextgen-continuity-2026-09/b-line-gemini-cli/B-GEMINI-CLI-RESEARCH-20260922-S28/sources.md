<!-- synthetic_only=true; production_verified=false -->
# S28 sources

This slice is offline synthetic research. No network, service, Gemini CLI, credentials, or external source was used. Therefore there are no factual external sources and no production verification. The harness oracle is an explicit test fixture rule, not evidence about production behavior.

- `fixtures/cases.json`: deterministic local input matrix (16 cases).
- `harness.py`: local deterministic classifier/oracle.
- `outputs/results.json`: generated local output.
