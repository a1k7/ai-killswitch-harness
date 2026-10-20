# AI Kill-Switch Verification Harness -- Makefile
#
# All Python invocations use .venv/bin/python so the venv is always the
# interpreter in use, regardless of whatever pytest/python is on $PATH.

PY        := .venv/bin/python
PIP       := .venv/bin/pip
PYTEST    := $(PY) -m pytest
ENV       := PYTHONPATH=src HARNESS_ENV=test

.PHONY: help venv install test test-fast demo api clean reset-db

help:
	@echo "Targets:"
	@echo "  venv        Create .venv with Python 3.11+ (idempotent)"
	@echo "  install     Install runtime + test deps into .venv"
	@echo "  test        Run the full test suite (quiet)"
	@echo "  test-fast   Run the test suite with -x (stop on first failure)"
	@echo "  demo        Run scripts/demo.py against a temp DB"
	@echo "  api         Run the FastAPI app on http://127.0.0.1:8000"
	@echo "  reset-db    Delete the local harness.db (destructive)"
	@echo "  clean       Remove .venv, __pycache__, .pytest_cache, harness.db"

venv:
	@if [ ! -x $(PY) ]; then \
		python3 -m venv .venv; \
	fi
	@$(PY) --version

install: venv
	$(PIP) install -U pip
	$(PIP) install -r requirements.txt

test: install
	$(ENV) $(PYTEST) tests/ -q

test-fast: install
	$(ENV) $(PYTEST) tests/ -q -x

demo: install
	PYTHONPATH=src $(PY) scripts/demo.py

api: install
	PYTHONPATH=src HARNESS_ENV=dev $(PY) -m uvicorn harness.app:create_app \
		--factory --host 127.0.0.1 --port 8000 --reload

reset-db:
	rm -f harness.db harness.db-wal harness.db-shm

clean: reset-db
	rm -rf .venv .pytest_cache src/harness/__pycache__ src/harness/mutants/__pycache__ tests/__pycache__ scripts/__pycache__