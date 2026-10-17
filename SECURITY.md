# Security Policy

Please do not report undisclosed vulnerabilities in public issues.

Until a dedicated security contact is configured, open a private GitHub security advisory where available, or contact the repository maintainer privately through the account's verified GitHub contact channel. Do not include credentials, tokens, private keys, or sensitive user data in reports.

The sidecar is a security-sensitive component. Reports involving command execution, Unix-socket authorization, workspace escape, process isolation, secret disclosure, or sandbox bypass should include a minimal reproducible case and the affected commit or version.

Runtime permissions, Skills/plugin loading, session recovery and interop grants
are also security-sensitive. Include the chosen permission mode and sandbox
backend in reports. The process sandbox is not OS isolation, and file-tool write
protection does not protect governance files from an explicitly allowed Shell.
See the [threat model](docs/concepts/threat-model.md) and
[current implementation boundary](docs/current-status.md).
