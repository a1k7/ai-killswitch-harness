"""Deliberately broken implementations used to prove detection capability.

Each mutant module exports:

    apply(monkeypatch, *, store, authz, killswitch, clock, app=None) -> None

`apply` installs a broken behavior on the module(s) named in that mutant's
docstring. Tests in tests/test_s10_mutants.py invoke `apply` then run the
normal assertions of the corresponding scenario and expect a specific failure.

These are NOT mocks of a result. Each mutant is a genuinely alternative code
path that deviates from the reference implementation at exactly one enforcement
point.
"""
"""Deliberately broken implementations used to prove detection capability."""