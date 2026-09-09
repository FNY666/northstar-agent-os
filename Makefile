.PHONY: help demo test ts-test install

help:
	@echo "northstar-agent-os targets:"
	@echo "  make demo    run the offline governed-loop demo (no API key needed)"
	@echo "  make test    run every component's test suite + repository doc tests"
	@echo "  make ts-test run the runtime's TypeScript face suite (needs node >= 22.6;"
	@echo "               without it the suite is skipped, not failed - the python drift"
	@echo "               gate in tests/test_typescript_sdk.py covers the same contract)"
	@echo "  make install install every component into a virtualenv (python3 -m venv .venv)"
	@echo ""
	@echo "per-component test suites (py3.10+, no PYTHONPATH needed - the test"
	@echo "modules bootstrap their sibling-component paths themselves):"
	@echo "  cd components/northstar-agent-runtime   && python3 -m unittest discover -s tests"
	@echo "  cd components/northstar-codex-sidecar   && python3 -m unittest discover -s tests"
	@echo "  cd components/northstar-run-contract    && python3 -m unittest discover -s tests"
	@echo "  cd components/northstar-host            && python3 -m unittest discover -s tests"
	@echo "  cd components/northstar-durable-run     && python3 -m unittest discover -s tests"
	@echo "  cd components/northstar-agent-interop   && python3 -m unittest discover -s tests"
	@echo ""
	@echo "TypeScript face (no npm install, no build: node runs the .ts sources directly):"
	@echo "  cd components/northstar-agent-runtime/sdk-ts && node --test \"test/*.test.ts\""

demo:
	sh examples/demo/run_offline.sh

test:
	@set -e; \
	for c in northstar-codex-sidecar northstar-run-contract northstar-host \
	         northstar-durable-run northstar-agent-interop northstar-agent-runtime; do \
		echo "== $$c =="; \
		(cd components/$$c && python3 -m unittest discover -s tests -p 'test_*.py'); \
	done; \
	$(MAKE) --no-print-directory ts-test; \
	echo "== repository documentation =="; \
	(cd tests && python3 -m unittest discover -s . -p 'test_*.py')

# The node run is guarded rather than assumed: native type stripping needs node >= 22.6, and a
# build image without node must stay green instead of failing on a missing tool. The contract the
# TypeScript face mirrors is checked from Python as well (tests/test_typescript_sdk.py), which is
# what makes that skip safe rather than a hole.
ts-test:
	@if node -e 'const [maj, min] = process.versions.node.split(".").map(Number); process.exit(maj > 22 || (maj === 22 && min >= 6) ? 0 : 1)' >/dev/null 2>&1; then \
		echo "== TypeScript face (node) =="; \
		(cd components/northstar-agent-runtime/sdk-ts && node --test "test/*.test.ts"); \
	else \
		echo "skip: TypeScript face needs node >= 22.6 (found: $$(node --version 2>/dev/null || echo none))"; \
	fi

install:
	python3 -m venv .venv
	./.venv/bin/python -m pip install --upgrade pip
	./.venv/bin/pip install ./components/northstar-run-contract
	./.venv/bin/pip install ./components/northstar-host
	./.venv/bin/pip install ./components/northstar-durable-run
	./.venv/bin/pip install ./components/northstar-agent-interop
	./.venv/bin/pip install ./components/northstar-agent-runtime
	@echo "installed into .venv:"
	@./.venv/bin/pip list 2>/dev/null | grep -i northstar
