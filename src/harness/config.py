"""Environment-driven settings. No hardcoded secrets; .env.example shows the knobs."""
from __future__ import annotations

import os
from dataclasses import dataclass


_TEST_DEFAULT_TOKEN = "recovery-token-dev-only-not-a-secret"


@dataclass(frozen=True)
class Settings:
    db_path: str
    policy_version: str
    initial_budget_minor: int
    recovery_token: str
    harness_env: str  # "test" | "dev" | "prod"
    staleness_window_us: int

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get("HARNESS_ENV", "dev").lower()
        token = os.environ.get("RECOVERY_TOKEN", _TEST_DEFAULT_TOKEN)
        if env == "prod" and token == _TEST_DEFAULT_TOKEN:
            raise RuntimeError(
                "RECOVERY_TOKEN must be set explicitly when HARNESS_ENV=prod"
            )
        return cls(
            db_path=os.environ.get("HARNESS_DB_PATH", "./harness.db"),
            policy_version=os.environ.get("HARNESS_POLICY_VERSION", "policy-v1"),
            initial_budget_minor=int(
                os.environ.get("HARNESS_INITIAL_BUDGET_MINOR", "10000")
            ),
            recovery_token=token,
            harness_env=env,
            staleness_window_us=int(
                os.environ.get("HARNESS_STALENESS_WINDOW_US", str(5 * 60 * 1_000_000))
            ),
        )

    @property
    def reset_enabled(self) -> bool:
        return self.harness_env == "test"


__all__ = ["Settings"]