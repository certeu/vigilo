"""Engine dependency provider.

Returns the configured ExecutionEngine. Real engines are constructed lazily so the
API imports cleanly even when Docker/Temporal client libs are absent (e.g. in the
test environment, where the dependency is overridden with FakeEngine anyway).
"""
from __future__ import annotations

from functools import lru_cache

from src.webapi.engine.base import ExecutionEngine
from src.webapi.settings import get_settings


@lru_cache
def _build_engine() -> ExecutionEngine:
    engine = get_settings().execution_engine
    if engine == "fake":
        from src.webapi.engine.fake import FakeEngine
        return FakeEngine()
    if engine == "mock":
        from src.webapi.engine.mock import MockEngine
        return MockEngine()
    if engine == "temporal":
        from src.webapi.engine.temporal import TemporalEngine
        return TemporalEngine()
    from src.webapi.engine.docker_temporal import DockerTemporalEngine
    return DockerTemporalEngine()


def get_engine() -> ExecutionEngine:
    return _build_engine()
