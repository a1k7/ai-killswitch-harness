"""Durable SQLite store. All mutating work happens inside BEGIN IMMEDIATE transactions.

NOTE: we deliberately do NOT use sqlite3.Connection.executescript() inside a
writer() transaction because executescript() performs an implicit COMMIT of any
pending transaction before running. Schema DDL is therefore applied as a list
of individual execute() calls.

Schema shape for `actions`: `rowid` is the primary key (integer). `action_id`
is a normal NOT NULL column, because the SAME action_id ("refund") can appear
in multiple distinct committed rows (each with its own decision_id). The two
uniqueness constraints that matter are:
    UNIQUE(decision_id)      -- one commit per decision
    UNIQUE(idempotency_key)  -- one commit per retry key
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .clock import Clock, RealClock
from .errors import HarnessError
from .schemas import SwitchState, SwitchStatus

_SCHEMA_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS kill_switch (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        state TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        policy_version TEXT NOT NULL,
        updated_at_us INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS budget (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        initial_minor INTEGER NOT NULL,
        remaining_minor INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS authorizations (
        decision_id TEXT PRIMARY KEY,
        epoch INTEGER NOT NULL,
        policy_version TEXT NOT NULL,
        issued_at_us INTEGER NOT NULL,
        expires_at_us INTEGER NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        request_json TEXT NOT NULL,
        signature_hex TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS actions (
        rowid INTEGER PRIMARY KEY,
        action_id TEXT NOT NULL,
        decision_id TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL,
        identity TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        committed_at_us INTEGER NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency (
        key TEXT PRIMARY KEY,
        outcome TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        action_id TEXT,
        decision_id TEXT,
        epoch INTEGER,
        recorded_at_us INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        recorded_at_us INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
    )
    """,
        """
    CREATE TABLE IF NOT EXISTS inflight_operations (
        operation_id TEXT PRIMARY KEY,
        decision_id TEXT NOT NULL,
        admitted_epoch INTEGER NOT NULL,
        admitted_at_us INTEGER NOT NULL,
        terminal_outcome TEXT,
        terminal_at_us INTEGER
    )
    """,
]


class DurableStateStore:
    def __init__(
        self,
        db_path: str | Path,
        clock: Optional[Clock] = None,
        readonly: bool = False,
    ) -> None:
        self.db_path = str(db_path)
        self.clock = clock or RealClock()
        self.readonly = readonly
        self._uri = f"file:{self.db_path}?mode=ro" if readonly else self.db_path

    # ---------------------------------------------------------------- connection
    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._uri,
            uri=self.readonly,
            isolation_level=None,  # manual transactions
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        if not self.readonly:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def writer(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE ... COMMIT. Serializes writers; check+write in one window."""
        if self.readonly:
            raise HarnessError("writer() not allowed on readonly store")
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    # ---------------------------------------------------------------- init
    def init_schema(
        self,
        *,
        initial_budget_minor: int = 10_000,
        policy_version: str = "policy-v1",
    ) -> None:
        """Idempotent. Creates tables and seeds singletons.

        Raises HarnessError if an old, incompatible `actions` schema is
        detected (pre-fix: action_id was PRIMARY KEY). Delete the DB and
        re-init in that case; this is a reference harness, not a migration
        project.
        """
        with self.writer() as conn:
            # Detect and reject old `actions` schema.
            cols = conn.execute("PRAGMA table_info(actions)").fetchall()
            if cols:
                pk_cols = [c["name"] for c in cols if int(c["pk"]) > 0]
                if pk_cols == ["action_id"]:
                    raise HarnessError(
                        "Incompatible `actions` schema (action_id is PRIMARY KEY). "
                        "Delete the database file and re-run init_schema()."
                    )
            for stmt in _SCHEMA_STATEMENTS:
                conn.execute(stmt)
            row = conn.execute("SELECT COUNT(*) AS c FROM kill_switch").fetchone()
            if int(row["c"]) == 0:
                conn.execute(
                    "INSERT INTO kill_switch (id, state, epoch, policy_version, updated_at_us)"
                    " VALUES (1, ?, ?, ?, ?)",
                    (SwitchState.ARMED.value, 1, policy_version, self.clock.now_us()),
                )
            row = conn.execute("SELECT COUNT(*) AS c FROM budget").fetchone()
            if int(row["c"]) == 0:
                conn.execute(
                    "INSERT INTO budget (id, initial_minor, remaining_minor) VALUES (1, ?, ?)",
                    (initial_budget_minor, initial_budget_minor),
                )

    # ---------------------------------------------------------------- switch
    def get_switch_conn(self, conn: sqlite3.Connection) -> SwitchStatus:
        row = conn.execute("SELECT * FROM kill_switch WHERE id = 1").fetchone()
        if row is None:
            raise HarnessError("kill_switch row missing; call init_schema()")
        return SwitchStatus(
            state=SwitchState(row["state"]),
            epoch=int(row["epoch"]),
            policy_version=str(row["policy_version"]),
            updated_at_us=int(row["updated_at_us"]),
        )

    def get_switch(self) -> SwitchStatus:
        with self.reader() as conn:
            return self.get_switch_conn(conn)

    # ---------------------------------------------------------------- budget
    def get_budget_remaining(self) -> int:
        with self.reader() as conn:
            row = conn.execute(
                "SELECT remaining_minor FROM budget WHERE id = 1"
            ).fetchone()
            if row is None:
                raise HarnessError("budget row missing; call init_schema()")
            return int(row["remaining_minor"])

    # ---------------------------------------------------------------- authorizations
    def get_authorization(self, decision_id: str) -> Optional[sqlite3.Row]:
        with self.reader() as conn:
            return conn.execute(
                "SELECT * FROM authorizations WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()

    def count_actions(self) -> int:
        with self.reader() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM actions").fetchone()
            return int(row["c"])

    def list_actions(self) -> list[sqlite3.Row]:
        with self.reader() as conn:
            return list(
                conn.execute(
                    "SELECT * FROM actions ORDER BY committed_at_us"
                ).fetchall()
            )

    # ---------------------------------------------------------------- audit read
    def list_audit(self) -> list[sqlite3.Row]:
        with self.reader() as conn:
            return list(
                conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq ASC"
                ).fetchall()
            )


__all__ = ["DurableStateStore"]