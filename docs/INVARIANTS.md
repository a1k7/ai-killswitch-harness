# In-Flight Cancellation Invariants

These invariants define what the harness claims to demonstrate for in-flight
protected operations when the kill switch trips. They are stated in terms a
test can check.

1. **Tripped denies new admissions.** After `KillSwitchController.trip()`
   returns, `InflightRegistry.admit()` raises `OperationDenied`. No action
   row is written.

2. **Admission ≠ commit.** An operation admitted while `ARMED` may still be
   rejected at `commit_protected_action()` if the switch state changed in the
   interim. The commit boundary is authoritative.

3. **Cancellation requested ≠ operation stopped.** `trip()` sets a
   `threading.Event` per in-flight operation and writes
   `INFLIGHT_CANCELLATION_REQUESTED`. A test must not treat the event being
   set, or the audit event being written, as evidence that the worker
   stopped. Only `INFLIGHT_TERMINAL_OUTCOME` with a specific value, or the
   absence of an `ACTION_COMMITTED` for the operation's decision, is
   evidence.

4. **Trip and commit are serialized by SQLite's writer lock.** Both
   operations begin with `BEGIN IMMEDIATE`, which acquires the SQLite writer
   lock. Whichever transaction calls `BEGIN IMMEDIATE` first is the
   linearization winner. This is the only synchronization mechanism used for
   the race. No Python-level lock is introduced, because that would risk an
   ABBA deadlock with SQLite's own lock and would not help against a
   non-cooperative worker.

5. **Recovery bumps the epoch.** `recover()` transitions `TRIPPED → ARMED`
   and increments the switch epoch. A decision issued at the pre-trip epoch
   fails the epoch check at commit. Admission records made pre-trip do not
   authorize post-recovery commits.

6. **Idempotency, cancellation, and budget are all checked in the same
   transaction.** There is no window in which a duplicate request can pass
   idempotency and then slip past the switch check.

7. **Evidence distinguishes request from outcome.**
   - `INFLIGHT_ADMITTED` — admission, not outcome.
   - `INFLIGHT_CANCELLATION_REQUESTED` — trip wrote the event, not an
     outcome.
   - `INFLIGHT_CANCELLATION_ACKNOWLEDGED` — worker observed the event.
   - `INFLIGHT_TERMINAL_OUTCOME` — worker's terminal state. One of:
     `cancelled_by_worker`, `rejected_at_commit`, `succeeded`, `unknown`.

8. **Tests do not rely on timing luck.** Concurrency tests use
   `threading.Event` or `threading.Barrier` for deterministic synchronization
   at the commit boundary or the trip boundary. `sleep()` is not used as a
   synchronization primitive.

## Out of scope / limitations

- The harness cannot forcibly and safely terminate an arbitrary Python
  thread. Cooperative cancellation is the only cancellation mechanism
  offered. Non-cooperative workers are handled by the commit boundary, which
  is authoritative regardless of the worker's behavior.

- The harness is a single-node, single-SQLite-file reference implementation.
  It does not demonstrate behavior under distributed consensus or
  multi-writer network conditions.

- Evidence integrity depends on hash-chain unbrokenness; an attacker who can
  rewrite the entire SQLite file and recompute the chain defeats
  `audit_chain_intact`. This limitation is inherited from the original
  harness and unchanged.