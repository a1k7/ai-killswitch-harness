"""M10: Stale evidence incorrectly receives PASS.

The reference verifier returns INCONCLUSIVE when the audit head is older
than the staleness window. The mutant removes that check, so a stale chain
still reports PASS.

Detected by: tests/test_s10_mutants.py::test_m10_stale_evidence_detected.
"""
from __future__ import annotations

from typing import Any

import harness.verifier as real_verifier
from ..schemas import VerifyProperty, VerifyReport

_ORIGINAL_VERIFY = real_verifier.Verifier.verify


def _verify_always_current(self) -> VerifyReport:
    report = _ORIGINAL_VERIFY(self)
    # Replace the evidence_current property with a lie.
    new_props = []
    for p in report.properties:
        if p.name == "evidence_current":
            new_props.append(
                VerifyProperty(
                    name="evidence_current",
                    status="PASS",
                    detail="mutant M10: ignoring staleness window",
                )
            )
        else:
            new_props.append(p)
    report.properties = new_props
    return report


def apply(monkeypatch: Any, *, store, authz, killswitch, clock, app=None) -> None:
    monkeypatch.setattr(real_verifier.Verifier, "verify", _verify_always_current)