"""Perf evidence tooling (T1 receipts/comparator, T2+ harnesses).

This directory is a regular package (not a namespace package like the
other scripts/ helpers) because the bare name ``perf`` collides with an
installed top-level ``perf`` extension module; without ``__init__.py``
``from perf.compare import ...`` resolves to that module instead.
"""
