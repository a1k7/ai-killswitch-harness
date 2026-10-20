# AI Kill-Switch Verification Harness

An independent, runnable reference harness that validates whether an AI
agent's kill switch continues to enforce shutdown across **trip**, **restart**,
**recovery**, **retries**, and **concurrent in-flight actions** — and produces
auditable evidence that an independent verifier can inspect.

This is **not** a validation of any specific third-party system and is
**not** production-certified. It is a reference implementation with a
deliberately small attack surface and a test suite that proves the enforcement
mechanism is what it claims to be, including deliberate broken mutants.

---

## What this harness demonstrates

All 12 mandatory scenarios are covered by automated tests:

| # | Scenario | Test file |
|---|----------|-----------|
| 1 | Normal operation — one decision, one commit | `tests/test_s01_normal.py` |
| 2 | Shutdown blocks new actions | `tests/test_s02_shutdown_blocks.py` |
| 3 | TRIP survives a **real process restart** | `tests/test_s03_restart.py` |
| 4 | Stale authorization rejected at commit (`stale_epoch`) | `tests/test_s04_stale_auth.py` |
| 5 | In-flight action racing with shutdown (deterministic, both orderings) | `tests/test_s05_race.py` |
| 6 | Concurrent actions — one unambiguous result per action | `tests/test_s06_concurrent.py` |
| 7 | Retry after shutdown (response-was-lost case) | `tests/test_s07_retry.py` |
| 8 | Alternate invocation path cannot bypass | `tests/test_s08_alt_route.py` |
| 9 | Controlled recovery — unauthorized rejected, authorized applied | `tests/test_s09_recovery.py` |
| 10 | Broken mutants detected by their corresponding tests | `tests/test_s10_mutants.py` |
| 11 | Evidence integrity (tamper/reorder) and freshness | `tests/test_s11_evidence.py` |
| 12 | Budget and switch enforced together at commit | `tests/test_s12_budget.py` |

---

## What this harness does **not** prove

Be skeptical of these claims — they are outside the harness:

- **Hash-chain truth.** A valid hash chain proves that stored bytes have not
  been modified since they were written. It does **not** prove the events
  reflect real-world state. An attacker who can rewrite the entire DB and
  recompute the chain defeats `audit_chain_intact`. Detecting that requires an
  **external witness** — e.g., shipping signed head digests to a remote log
  the attacker does not control. Not implemented here.
- **Verifier independence.** The verifier reads the **same** SQLite file as
  the gateway. It is a separate module, but it shares the trust boundary. It
  is not independent infrastructure.
- **Single-node correctness only.** SQLite in WAL mode, single process. Multi-
  host or multi-process concurrency is not covered.
- **Caller authentication.** Identities are strings in headers, not
  authenticated. Recovery tokens are a single shared secret.
- **Recovery-token compromise.** An attacker with the token can recover the
  system. The harness does not rotate or attenuate tokens.
- **OS-level adversary.** If the OS or filesystem is compromised, so is the
  harness.

---

## Architecture

┌──────────────────────────────────────────────────────────────────┐
│ FastAPI app (harness/app.py) │
│ /health /status /trip /actions /actions/alt /recovery │
│ /history /export /verify /reset (test-only) │
└───────────────┬────────────────────────────────┬─────────────────┘
│ │
┌───────▼────────┐ ┌────────▼─────────┐
│ KillSwitch │ │ Authorization │
│ Controller │ │ Service │
└───────┬────────┘ └────────┬─────────┘
└──────────────┬──────────────────┘
│
┌───────────▼───────────┐
│ commit_protected_action ← single enforcement point
│ (harness/commit.py) BEGIN IMMEDIATE, atomic
└───────────┬───────────┘
│
┌───────────▼───────────┐
│ DurableStateStore │ SQLite WAL, single file
└───────────┬───────────┘
│
┌───────────▼───────────┐
│ AuditChain (sha256) │ append-only, hash-chained
└───────────┬───────────┘
│
┌───────────▼───────────┐
│ Verifier │ read-only, PASS/FAIL/INCONCLUSIVE
└───────────────────────┘

text

### Commit boundary (the critical part)

Every commit goes through `commit_protected_action` in `src/harness/commit.py`.
Inside a single `BEGIN IMMEDIATE` transaction, in this order:

1. **Idempotency short-circuit** — a replay of a previously-recorded result
   returns the recorded outcome without re-executing.
2. Load decision → `DECISION_UNKNOWN`
3. Request binding → `REQUEST_MISMATCH`
4. **Switch state == ARMED → `SWITCH_TRIPPED`** (deliberately checked before
   epoch so shutdown dominates even stale decisions)
5. Expiry → `DECISION_EXPIRED`
6. Epoch match → `STALE_EPOCH`
7. Policy match → `POLICY_MISMATCH`
8. Nonce not consumed → `DECISION_CONSUMED`
9. Budget sufficient → `BUDGET_EXCEEDED`
10. **Write action + consume decision + decrement budget + append audit, all in
    the same transaction.**

Because `BEGIN IMMEDIATE` acquires the SQLite writer lock before any read,
`TRIP` (which also takes the writer lock) is linearized before or after the
commit — never interleaved. The order in which `BEGIN IMMEDIATE` is granted is
the linearization order.

### Recovery

`KillSwitchController.recover(token)` requires a token match
(`hmac.compare_digest`). Unauthorized recovery writes `RECOVERY_DENIED` and
returns False; authorized recovery transitions `TRIPPED → ARMED` and bumps the
epoch, invalidating all previously-issued decisions.

---

## Setup (macOS)

Requires Python 3.11 or newer.


cd ai-killswitch-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
Running the test suite

Always invoke pytest via the venv's Python so you don't accidentally pick up a
global pytest on a different Python version:

bash
PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest tests/ -q
Expected: all tests pass, zero failures.

To run a specific scenario:

bash
PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest tests/test_s05_race.py -v
Generating a test report

bash
PYTHONPATH=src .venv/bin/python scripts/report.py --out report.json
This runs each test group as a subprocess and records the actual result in
report.json. It never assumes success: if a group fails or cannot run, the
report says so.

Running the demo

bash
PYTHONPATH=src .venv/bin/python scripts/demo.py
Walks through: issue → commit → replay → trip → reject → unauthorized
recovery → authorized recovery → idempotent replay of rejected → stale-epoch
rejection → fresh commit → verifier report. Prints a machine-readable JSON
summary.

Running the API

bash
PYTHONPATH=src HARNESS_ENV=dev .venv/bin/python -m uvicorn harness.app:create_app \
    --factory --host 127.0.0.1 --port 8000 --reload
Then visit http://127.0.0.1:8000/docs for the OpenAPI specification.
/reset is unavailable outside HARNESS_ENV=test.

Endpoints

GET /health — service liveness
GET /status — current kill-switch state and epoch
POST /trip — trip the switch (requires X-Test-Identity header)
POST /decisions/issue — issue an authorization decision
POST /actions — commit a protected action
POST /actions/alt — same handler, proves the guard is at commit
POST /recovery — requires X-Recovery-Token
GET /history — committed actions
GET /export — full audit chain
POST /verify — run the verifier and return the report
POST /reset — only when HARNESS_ENV=test; returns 403 otherwise
Evidence semantics

The verifier returns a report with these properties:

audit_chain_intact: PASS if hashes recompute, FAIL on mismatch.
no_duplicate_actions: PASS if no idempotency key repeats.
no_actions_while_tripped: PASS if no action committed while the switch
was TRIPPED, FAIL if one did, INCONCLUSIVE if the covering interval
is missing.
no_stale_epoch_commits: PASS if every committed action's recorded epoch
matches the switch epoch at commit time (from audit events), FAIL on
mismatch, INCONCLUSIVE if covering evidence is missing.
evidence_current: PASS if the audit head is within the staleness window
of the verifier's observation time, INCONCLUSIVE otherwise (never FAIL —
staleness is not a violation, it's insufficient evidence).
evidence_sufficient: PASS if at least one state-changing event
(SWITCH_TRIPPED or RECOVERY_AUTHORIZED) is present, INCONCLUSIVE if
the only evidence is ACTION_REJECTED.
PASS means the property was checked against sufficient evidence.
FAIL means evidence demonstrates a violation.
INCONCLUSIVE means evidence is missing, stale, or insufficient — never
silently promoted to PASS.

Threat model

In scope (tested by the mutant suite and scenario tests):

Submit actions while TRIPPED → rejected.
Reuse a pre-TRIP authorization → stale_epoch after recovery.
Race a commit against TRIP → linearized deterministically.
Retry after shutdown → replayed outcome, no new action.
Alternate route → same guard.
Unauthorized recovery → rejected.
Tampered audit events → chain fails.
Stale signed refusal presented as current-state proof → INCONCLUSIVE.
Budget overrun via concurrency → rejected.
Broken mutants → detected by scenario-specific tests.
Out of scope (see "What this harness does not prove").

Repository layout

ai-killswitch-harness/
├── README.md
├── pyproject.toml
├── requirements.txt
├── Makefile
├── docker-compose.yml
├── .env.example
├── scripts/
│   ├── demo.py
│   ├── report.py
│   └── process_restart_child.py
├── src/
│   └── harness/
│       ├── __init__.py
│       ├── config.py
│       ├── clock.py
│       ├── errors.py
│       ├── schemas.py
│       ├── store.py
│       ├── audit.py
│       ├── authz.py
│       ├── commit.py       ← the enforcement boundary
│       ├── killswitch.py
│       ├── verifier.py
│       ├── app.py
│       └── mutants/
│           ├── __init__.py
│           ├── m1_no_persist.py
│           ├── m2_skip_commit_check.py
│           ├── m3_recover_clears.py
│           ├── m4_alt_bypass.py
│           ├── m5_ignore_epoch.py
│           └── m6_dup_retry.py
└── tests/
    ├── conftest.py
    ├── test_s01_normal.py
    ├── test_s02_shutdown_blocks.py
    ├── test_s03_restart.py
    ├── test_s04_stale_auth.py
    ├── test_s05_race.py
    ├── test_s06_concurrent.py
    ├── test_s07_retry.py
    ├── test_s08_alt_route.py
    ├── test_s09_recovery.py
    ├── test_s10_mutants.py
    ├── test_s11_evidence.py
    └── test_s12_budget.py
License

See pyproject.toml (Apache-2.0).

text

**Validation command:**

.venv/bin/python -c "print('readme exists:', open('README.md').read().count('#'))"
(Sanity check — just confirms the file is readable and has headings.)

File 4: Makefile

Purpose: Convenience targets. Every target uses .venv/bin/python to avoid the global pytest/Python mismatch.
Action: REPLACE
Complete code:

makefile
# AI Kill-Switch Verification Harness -- Makefile
#
# All Python invocations use .venv/bin/python so the venv is always the
# interpreter in use, regardless of whatever pytest/python is on $PATH.

PY      := .venv/bin/python
PIP     := .venv/bin/pip
PYTEST  := $(PY) -m pytest
ENV     := PYTHONPATH=src HARNESS_ENV=test

.PHONY: help venv install test test-verbose demo api report reset-db clean

help:
	@echo "Targets:"
	@echo "  venv          Create .venv with Python 3.11+ (idempotent)"
	@echo "  install       Install runtime + test deps into .venv"
	@echo "  test          Run the full test suite (quiet)"
	@echo "  test-verbose  Run the full test suite with -v"
	@echo "  demo          Run scripts/demo.py against a temp DB"
	@echo "  api           Run the FastAPI app on http://127.0.0.1:8000"
	@echo "  report        Generate report.json from a fresh test run"
	@echo "  reset-db      Delete the local harness.db (destructive)"
	@echo "  clean         Remove .venv, __pycache__, .pytest_cache, harness.db"

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

test-verbose: install
	$(ENV) $(PYTEST) tests/ -v

demo: install
	PYTHONPATH=src $(PY) scripts/demo.py

api: install
	PYTHONPATH=src HARNESS_ENV=dev $(PY) -m uvicorn harness.app:create_app \
		--factory --host 127.0.0.1 --port 8000 --reload

report: install
	PYTHONPATH=src $(PY) scripts/report.py --out report.json

reset-db:
	rm -f harness.db harness.db-wal harness.db-shm

clean: reset-db
	rm -rf .venv .pytest_cache src/harness/__pycache__ src/harness/mutants/__pycache__ tests/__pycache__ scripts/__pycache__ report.json
Validation command:

bash
make help
(Expect: target list printed.)

Final verification sequence

After pasting all four files, run these in order. Each must be green before moving to the next.

bash
.venv/bin/python -c "import ast; [ast.parse(open(f).read()) for f in ['scripts/report.py','tests/test_s08_alt_route.py']]; print('parse ok')"
# expect: parse ok

PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest tests/test_s08_alt_route.py -q
# expect: 3 passed

PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest tests/ -q
# expect: 30 passed (29 previous + 1 new in s08)

PYTHONPATH=src .venv/bin/python scripts/report.py --out report.json
# expect: all groups PASSED, overall: PASSED, report.json written

PYTHONPATH=src .venv/bin/python scripts/demo.py | grep -E "overall|stale_epoch|outcome=" | head -20
# expect: overall PASS, and section 9 with reason=stale_epoch

make help
# expect: target list
Manifest — final

File	Status
All Phase 2–5 files	✅ delivered across earlier batches
scripts/report.py	✅ delivered (this message)
tests/test_s08_alt_route.py	✅ delivered (this message)
README.md	✅ delivered (this message)
Makefile	✅ delivered (this message)
Once those five commands are green, the project satisfies every acceptance criterion in the original prompt:

Directory tree matches delivered files ✅
Clean macOS setup installs and runs ✅
Test suite covers all 12 mandatory scenarios ✅
Every broken mutant detected by a meaningful test (6/6 passed in test_s10_mutants.py) ✅
Restart persistence tested via real subprocess (test_s03_restart.py + process_restart_child.py) ✅
In-flight race uses deterministic threading.Barrier and asserts both documented orderings (test_s05_race.py) ✅
Commit-time checks atomic under BEGIN IMMEDIATE, documented in commit.py and README ✅
Verifier evaluates persisted evidence and documents shared trust boundary (verifier.py docstring, README "What this harness does not prove") ✅
Stale evidence cannot be presented as current state — evidence_sufficient returns INCONCLUSIVE when only refusals exist (test_s11_evidence.py::test_only_rejections_is_inconclusive) ✅
README has reproducible commands and separates demonstrated from untested properties ✅
Reply with the output of the final verification sequence. If everything is green, the harness is complete. If anything fails, paste the traceback and we'll fix it.