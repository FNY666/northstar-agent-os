# Task fixture

`isAllowedUrl(raw, origins)` permits only HTTPS URLs whose normalized origin is explicitly listed. Reject credentials, malformed URLs, suffix/userinfo bypasses, and ports absent from the allowlist. Default HTTPS port 443 is canonical.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
