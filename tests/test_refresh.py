from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from wheelguard.database import Database
from wheelguard.models import AdvisoryResult, ProjectResponse, SimplePayload
from wheelguard.policy import MinimumAgePolicy
from wheelguard.refresh import AdvisoryRefresher


class RecordingAdvisoryPolicy:
    def __init__(self) -> None:
        self.projects: list[str] = []

    async def apply(self, project: str, payload: SimplePayload) -> AdvisoryResult:
        self.projects.append(project)
        return AdvisoryResult(payload, "MISS")


def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_refreshes_only_recently_requested_cached_projects(tmp_path: Path) -> None:
    now = datetime(2026, 9, 1, tzinfo=UTC)
    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    payload = {
        "files": [
            {
                "filename": "demo-1.0.tar.gz",
                "upload-time": "2025-01-01T00:00:00Z",
            }
        ]
    }
    await database.put_project("active", ProjectResponse(payload), fetched_at=now)
    await database.put_project("inactive", ProjectResponse(payload), fetched_at=now)
    await database.record_advisory_target("active", requested_at=now - timedelta(days=1))
    await database.record_advisory_target("inactive", requested_at=now - timedelta(days=31))
    await database.record_advisory_target("uncached", requested_at=now)
    policy = RecordingAdvisoryPolicy()
    refresher = AdvisoryRefresher(
        database,
        policy,
        MinimumAgePolicy(timedelta(days=14)),
        active_window=timedelta(days=30),
        clock=lambda: now,
    )

    evaluated = await refresher.refresh_once()

    assert evaluated == 1
    assert policy.projects == ["active"]
    assert await database.list_advisory_targets(requested_since=now - timedelta(days=40)) == ["active"]
