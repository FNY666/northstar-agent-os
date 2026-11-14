# Northstar AgentOS Snapshot

This directory is a snapshot import from the local `northstar-integrated` tree. It is prepared on top of public `main` as a new branch and must be reviewed through a pull request. It does not overwrite public main and does not claim architectural integration with the current public `northstar-agent-runtime` tree.

Source commit: `c348641bd56df7fe4f467de670f84d8a3161ee4b`
Original local tree files: 179

The snapshot excludes private audit workspaces, credentials, environment values, remote URLs, and the unmerged Claude Router r2 candidate. A public leak audit found no confirmed usable credential but retains manual-review candidates; this snapshot must not be published until the final PR review confirms the allowed file scope.
