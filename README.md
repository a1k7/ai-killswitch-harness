# AI Kill-Switch Verification Harness

An independent, runnable reference harness that validates whether an AI
agent's kill switch continues to enforce shutdown across **trip**, **restart**,
**recovery**, **retries**, **concurrent in-flight actions**, and **in-flight
cancellation**.

This is **not** a validation of any specific third-party system and is
**not** production-certified. It is a reference implementation with a
deliberately small attack surface and a test suite that proves the enforcement
mechanism is what it claims to be, including deliberate broken mutants.

The report produced by this harness applies to *this implementation* only.
It does not reproduce or validate any other system.

---

## What this harness demonstrates

### Original scenarios (1–12)

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
| 10 | Broken mutants M1–M10 detected by their corresponding tests | `tests/test_s10_mutants.py` |
| 11 | Evidence integrity (tamper/reorder) and freshness | `tests/test_s11_evidence.py` |
| 12 | Budget and switch enforced together at commit | `tests/test_s12_budget.py` |

### In-flight cancellation extension (Tests A–J, mutants M11–M16)

| Test | Scenario | File |
|------|----------|------|
| A | Control case: normal completion | `tests/test_s13_inflight_basic.py` |
| B | Kill switch trips before admission | same |
| C | Kill switch trips during execution (cooperative) | same |
| D | In-flight operation attempts to commit after trip (non-cooperative) | same |
| E | Cancellation race (three orderings) | `tests/test_s13_inflight_race.py` |
| F | Multiple in-flight operations | same |
| G | Cancellation failure / non-cooperative worker | same |
| H | Restart and recovery with outstanding operations | `tests/test_s13_inflight_recovery.py` |
| I | Idempotency and retry after cancellation | same |
| J | Evidence integrity across admission/cancel/terminal events | same |
| M11–M16 | Detection tests for the six in-flight mutants | `tests/test_s14_inflight_mutants.py` |

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
- **Forcible termination.** Python cannot safely terminate an arbitrary thread.
  Cancellation is cooperative only; non-cooperative workers are handled by the
  commit boundary. See "In-flight cancellation" below.
- **Remote side effects.** If the protected side effect happens on a remote
  system that does not share the SQLite transaction, this harness cannot
  demonstrate that the remote system refuses the side effect. It proves the
  commit boundary refuses it.

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
the linearization order. **This is the only synchronization mechanism used for
the trip-vs-commit race.** No Python-level lock is introduced: a thread-held
lock would risk an ABBA deadlock with SQLite's own lock and would not help
against a non-cooperative worker.

### Recovery

`KillSwitchController.recover(token)` requires a token match
(`hmac.compare_digest`). Unauthorized recovery writes `RECOVERY_DENIED` and
returns False; authorized recovery transitions `TRIPPED → ARMED` and bumps the
epoch, invalidating all previously-issued decisions. Recovery never revives
an in-flight operation.

---

## In-flight cancellation (extension)

The base harness demonstrated that the kill switch rejects *new* actions and
prevents the commit of *stale* authorizations. The extension models what
happens to a protected operation that has been **admitted** but has not yet
**committed** its side effect when the switch trips.

### Design summary

- `InflightRegistry.admit(decision_id)` registers an operation and returns a
  per-operation `threading.Event`. Admission is denied if the switch is not
  ARMED at the moment of admission.
- `KillSwitchController.trip()` acquires the SQLite writer lock, transitions
  the switch to TRIPPED, bumps the epoch, and — inside the same transaction —
  calls `InflightRegistry.cancel_all()`. That writes
  `INFLIGHT_CANCELLATION_REQUESTED` events and sets each operation's
  cancel event.
- Cancellation is **advisory**. A cooperative worker observes the event, calls
  `acknowledge_cancellation()`, and either completes without committing or
  records `INFLIGHT_TERMINAL_OUTCOME=cancelled_by_worker`. A **non-cooperative**
  worker ignores the event and calls `commit_protected_action()` anyway; the
  commit boundary independently re-reads the switch state and rejects with
  `switch_tripped`.
- The commit boundary remains the single authoritative enforcement point.

### Two-layer defense

The reference enforces two independent invariants at the commit boundary:
`switch.state == ARMED` and `decision.epoch == switch.epoch`. A mutant that
removes only the first (as the original M12 was drafted to do) is caught by
the second — the trip bumped the epoch, so a stale decision fails with
`STALE_EPOCH`. This is **defense in depth**. The final M12 mutant
(see `src/harness/mutants/m12_commit_skips_switch.py`) bypasses both to
demonstrate the successful-commit scenario. The suite proves both
single-layer and dual-layer bypasses are detectable.

### In-flight evidence events

The audit chain records these events during the lifecycle:

| Event | Written by | Meaning |
|---|---|---|
| `INFLIGHT_ADMITTED` | `admit()` | Operation recorded, not yet terminal |
| `INFLIGHT_CANCELLATION_REQUESTED` | `trip()` | Cancellation signal sent (not proof of stop) |
| `INFLIGHT_CANCELLATION_ACKNOWLEDGED` | worker | Worker observed the signal |
| `INFLIGHT_TERMINAL_OUTCOME` | worker or `record_terminal()` | One of `cancelled_by_worker`, `rejected_at_commit`, `succeeded`, `unknown` |

A cancellation request alone is **not** evidence that the operation stopped.
Only the presence of a terminal outcome, or the absence of an
`ACTION_COMMITTED` for the operation's decision, establishes the outcome.

### In-flight mutants (M11–M16)

| ID | Defect | Invariant violated |
|---|---|---|
| M11 | `trip()` does not fan out `cancel_all()` | Trip must signal cancellation to in-flight operations |
| M12 | Commit boundary skips switch **and** epoch | Commit enforces switch state; epoch is defense-in-depth |
| M13 | Commit boundary skips epoch check only | Commit must reject stale pre-trip decisions after recovery |
| M14 | `record_terminal()` overwrites a SUCCEEDED record with CANCELLED | Terminal outcome must be recorded exactly once |
| M15 | `/actions/alt` writes an action without going through commit | Alternate routes must not bypass in-flight enforcement |
| M16 | `recover()` clears cancel events and rolls epoch back to 1 | Recovery must not revive invalid in-flight operations |

The full invariant list is documented in `docs/INVARIANTS.md`.

---

## Setup (macOS)

Requires Python 3.11 or newer.

```bash
cd ai-killswitch-harness
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

Running the test suite

Always invoke pytest via the venv's Python so you don't accidentally pick up
a global pytest on a different Python version:

bash
PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest tests/ -q
Expected: all tests pass, zero failures. The reference suite has 54 tests:
34 from the original harness, 20 from the in-flight cancellation extension.

To run a specific scenario or group:

bash
# In-flight tests only
PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest \
    tests/test_s13_inflight_basic.py \
    tests/test_s13_inflight_race.py \
    tests/test_s13_inflight_recovery.py \
    tests/test_s14_inflight_mutants.py -q

# Just the mutation suite
PYTHONPATH=src HARNESS_ENV=test .venv/bin/python -m pytest \
    tests/test_s10_mutants.py tests/test_s14_inflight_mutants.py -v
Generating a test report

bash
PYTHONPATH=src .venv/bin/python scripts/report.py --out report.json
This runs each test group as a subprocess and records the actual result
in report.json. It never assumes success: if a group fails or cannot run,
the report says so. The mutation matrix section of the report covers M1–M16
and records, per mutant: its description, the invariant it violates, the test
that detects it, the expected result, and the observed result.

Expected: overall: PASSED, 16/16 mutants detected.

Running the demo

bash
PYTHONPATH=src .venv/bin/python scripts/demo.py
Walks through: issue → commit → replay → trip → reject → unauthorized
recovery → authorized recovery → idempotent replay of rejected → stale-epoch
rejection → fresh commit → verifier report. Prints a machine-readable JSON
summary. The stale-epoch rejection at section 9 is the specific case that
proves pre-trip decisions are correctly classified after recovery.

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
Race a commit against TRIP → linearized deterministically by SQLite's
writer lock.
Retry after shutdown → replayed outcome, no new action.
Alternate route → same guard.
Unauthorized recovery → rejected.
Tampered audit events → chain fails.
Stale signed refusal presented as current-state proof → INCONCLUSIVE.
Budget overrun via concurrency → rejected.
In-flight operation admitted before trip, commits after trip → rejected by
the commit boundary.
Cooperative cancellation observed → recorded as terminal outcome.
Non-cooperative worker ignores cancellation → rejected at commit.
Broken mutants M1–M16 → detected by scenario-specific tests.
Out of scope — see "What this harness does not prove".

Repository layout

ai-killswitch-harness/
├── README.md
├── pyproject.toml
├── requirements.txt
├── Makefile
├── docker-compose.yml
├── .env.example
├── docs/
│   └── INVARIANTS.md          ← in-flight cancellation invariants
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
│       ├── commit.py          ← the enforcement boundary
│       ├── inflight.py        ← in-flight registry + cooperative cancellation
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
│           ├── m6_dup_retry.py
│           ├── m7_idempotency_different_payload.py
│           ├── m8_reuse_consumed_auth.py
│           ├── m9_budget_overspend.py
│           ├── m10_stale_evidence_pass.py
│           ├── m11_trip_skips_cancel.py
│           ├── m12_commit_skips_switch.py
│           ├── m13_commit_skips_epoch.py
│           ├── m14_lie_terminal.py
│           ├── m15_alt_route_bypass.py
│           └── m16_recover_revives.py
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
    ├── test_s12_budget.py
    ├── test_s13_inflight_basic.py
    ├── test_s13_inflight_race.py
    ├── test_s13_inflight_recovery.py
    └── test_s14_inflight_mutants.py


    Reference harness scope

This is a reference harness, not a validation of any production system.
The results in report.json apply to this implementation and to the
invariants in docs/INVARIANTS.md. They do not reproduce, validate, or extend
to any other system, including cMCP.

If a reviewer wishes to use this harness as a template for validating another
system, the required work is:

Inspect that system's actual commit boundary and cancellation primitives.
Write equivalent tests against its real interfaces.
Run them and record the actual outputs.
The harness here is a model of one correct design, not a proof of your
design.

License

See pyproject.toml (Apache-2.0).


### Validation command

```bash
wc -l README.md
grep -c "^## " README.md

Expected:

~380 README.md (a bit more than the previous 250-ish, since we added the extension sections)
~11 top-level headings (##  lines)
