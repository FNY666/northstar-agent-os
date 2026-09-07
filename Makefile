.PHONY: help demo test install

help:
	@echo "northstar-agent-os targets:"
	@echo "  make demo    run the offline governed-loop demo (no API key needed)"
	@echo "  make test    run every component's test suite + repository doc tests"
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

demo:
	sh examples/demo/run_offline.sh

test:
	@set -e; \
	for c in northstar-codex-sidecar northstar-run-contract northstar-host \
	         northstar-durable-run northstar-agent-interop northstar-agent-runtime; do \
		echo "== $$c =="; \
		(cd components/$$c && python3 -m unittest discover -s tests -p 'test_*.py'); \
	done; \
	echo "== repository documentation =="; \
	(cd tests && python3 -m unittest discover -s . -p 'test_*.py')

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
