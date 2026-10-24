"""Shared pytest fixtures. Deterministic clock; isolated temp DB per test."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.authz import AuthorizationService
from harness.clock import ManualClock
from harness.config import Settings
from harness.inflight import InFlightRegistry
from harness.killswitch import KillSwitchController
from harness.store import DurableStateStore

TEST_RECOVERY_TOKEN = "test-recovery-token"


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "harness.db"


@pytest.fixture
def store(db_path: Path, clock: ManualClock) -> DurableStateStore:
    s = DurableStateStore(str(db_path), clock)
    s.init_schema(initial_budget_minor=10_000, policy_version="policy-v1")
    return s


@pytest.fixture
def authz(store: DurableStateStore, clock: ManualClock) -> AuthorizationService:
    return AuthorizationService(store, clock)


@pytest.fixture
def inflight(store: DurableStateStore, clock: ManualClock) -> InFlightRegistry:
    return InFlightRegistry(store, clock)


@pytest.fixture
def killswitch(
    store: DurableStateStore, clock: ManualClock, inflight: InFlightRegistry
) -> KillSwitchController:
    return KillSwitchController(
        store, clock, recovery_token=TEST_RECOVERY_TOKEN, inflight=inflight,
    )


@pytest.fixture
def settings(db_path: Path, tmp_path: Path) -> Settings:
    return Settings(
        db_path=str(db_path),
        policy_version="policy-v1",
        initial_budget_minor=10_000,
        recovery_token=TEST_RECOVERY_TOKEN,
        harness_env="test",
        staleness_window_us=5 * 60 * 1_000_000,
    )


@pytest.fixture
def app(settings: Settings, clock: ManualClock):
    from harness.app import create_app
    return create_app(settings=settings, clock=clock)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app)