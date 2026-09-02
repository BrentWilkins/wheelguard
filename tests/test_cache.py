from datetime import timedelta
from pathlib import Path

import pytest

from wheelguard.cache import CachingRepository
from wheelguard.database import Database
from wheelguard.models import ProjectResponse, UpstreamRepositoryError


class CountingRepository:
    def __init__(self, *, fail_after_first: bool = False) -> None:
        self.calls = 0
        self.fail_after_first = fail_after_first

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        self.calls += 1
        if self.fail_after_first and self.calls > 1:
            raise UpstreamRepositoryError("offline")
        return ProjectResponse({"name": normalized_name, "files": []}, "10")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_fresh_metadata_is_served_without_an_upstream_request(tmp_path: Path) -> None:
    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    upstream = CountingRepository()
    repository = CachingRepository(upstream, database, ttl=timedelta(minutes=5))

    first = await repository.get_project("demo")
    second = await repository.get_project("demo")

    assert first.cache_status == "MISS"
    assert second.cache_status == "HIT"
    assert upstream.calls == 1


@pytest.mark.anyio
async def test_stale_metadata_is_used_when_upstream_is_offline(tmp_path: Path) -> None:
    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    upstream = CountingRepository(fail_after_first=True)
    repository = CachingRepository(upstream, database, ttl=timedelta(seconds=-1))

    await repository.get_project("demo")
    fallback = await repository.get_project("demo")

    assert fallback.cache_status == "STALE"
    assert upstream.calls == 2
