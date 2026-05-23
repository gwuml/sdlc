PYTHON ?= python3

.PHONY: test validate smoke

test:
	$(PYTHON) -m unittest discover -s tests

validate:
	$(PYTHON) -m sdlc validate

smoke:
	$(PYTHON) -m sdlc init
	$(PYTHON) -m sdlc plan "Build RBAC dashboard" --run-id smoke-rbac
	$(PYTHON) -m sdlc validate --run-id smoke-rbac
	$(PYTHON) -m sdlc run smoke-rbac --redteam
	$(PYTHON) -m sdlc report smoke-rbac --print
