# S17 sources

Access date: 2026-09-22.

1. W3C Trace Context — https://www.w3.org/TR/trace-context/ — verified: trace-context propagation and processing semantics; cannot prove complete collection or external effects.
2. W3C Baggage — https://www.w3.org/TR/baggage/ — verified: baggage is application context and may be modified/removed; cannot act as authorization or durable evidence.
3. OpenTelemetry Logs Data Model — https://opentelemetry.io/docs/specs/otel/logs/data-model/ — verified: log timestamp and optional trace/span correlation fields; cannot prove delivery/retention/completeness.
4. DSSE Envelope specification — https://github.com/secure-systems-lab/dsse/blob/master/envelope.md — verified: signed envelopes bind signatures to payloads; cannot prove payload truth or external commit.

Evidence window for each: public first-party documentation retrieved on 2026-09-22; page content and stated scope only. No production or private evidence was used.
