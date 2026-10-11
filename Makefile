.PHONY: setup seed dev test test-fast lint bench

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
PYTHON   ?= python
PIP      ?= pip
UVICORN  ?= uvicorn
PYTEST   ?= pytest
RUFF     ?= ruff
MYPY     ?= mypy

BACKEND_DIR  = backend
SEED_SCRIPT  = seed/seed.py
DB_FILE      ?= sentinel.db
REPORTS_DIR  = reports

# ─────────────────────────────────────────────
# setup: install all dependencies
# ─────────────────────────────────────────────
setup:
	$(PIP) install -r requirements.txt

# ─────────────────────────────────────────────
# seed: delete DB and rebuild all synthetic data
# ─────────────────────────────────────────────
seed:
	$(PYTHON) $(SEED_SCRIPT) --db $(DB_FILE)

# ─────────────────────────────────────────────
# dev: start backend with reload (frontend is separate)
# ─────────────────────────────────────────────
dev:
	SENTINEL_DB=$(DB_FILE) $(UVICORN) backend.app.main:app --reload --host 0.0.0.0 --port 8000

# ─────────────────────────────────────────────
# test: full backend test suite
# ─────────────────────────────────────────────
test:
	@mkdir -p $(REPORTS_DIR)
	SENTINEL_DB=:memory: SENTINEL_TESTING=1 $(PYTEST) $(BACKEND_DIR)/tests -v \
	    --tb=short -p no:cacheprovider 2>&1 | tee $(REPORTS_DIR)/last_run.txt
	@echo "Tests complete."

# ─────────────────────────────────────────────
# test-fast: unit tests only (no e2e, no bench)
# ─────────────────────────────────────────────
test-fast:
	@mkdir -p $(REPORTS_DIR)
	SENTINEL_DB=:memory: SENTINEL_TESTING=1 $(PYTEST) $(BACKEND_DIR)/tests -v \
	    -m "not e2e and not bench" --tb=short 2>&1 | tee $(REPORTS_DIR)/last_run_fast.txt

# ─────────────────────────────────────────────
# lint: ruff + mypy
# ─────────────────────────────────────────────
lint:
	$(RUFF) check $(BACKEND_DIR) seed
	$(MYPY) $(BACKEND_DIR)/app seed

# ─────────────────────────────────────────────
# bench: PromptShield benchmark on test split only
# ─────────────────────────────────────────────
bench:
	@mkdir -p $(REPORTS_DIR)
	SENTINEL_DB=$(DB_FILE) $(PYTHON) -m backend.app.promptshield.bench \
	    --split test --out $(REPORTS_DIR)/benchmark.json
	@echo "Benchmark written to $(REPORTS_DIR)/benchmark.json"
