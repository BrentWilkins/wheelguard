import hashlib
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from wheelguard.application import create_app
from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.config import Settings
from wheelguard.database import Database
from wheelguard.models import ProjectResponse, UpstreamRepositoryError
from wheelguard.simple_api import SIMPLE_JSON


class OnlineRepository:
    def __init__(self, digest: str, size: int) -> None:
        self._digest = digest
        self._size = size

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        return ProjectResponse(
            {
                "meta": {"api-version": "1.4"},
                "name": normalized_name,
                "files": [
                    {
                        "filename": "demo-1.0-py3-none-any.whl",
                        "url": "https://files.example/demo.whl",
                        "hashes": {"sha256": self._digest},
                        "size": self._size,
                        "upload-time": "2020-01-01T00:00:00Z",
                    }
                ],
            }
        )


class OfflineRepository:
    async def get_project(self, normalized_name: str) -> ProjectResponse:
        raise UpstreamRepositoryError("offline")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_warmed_project_survives_complete_upstream_outage(tmp_path: Path) -> None:
    wheel = b"verified wheel content"
    digest = hashlib.sha256(wheel).hexdigest()
    settings = Settings(
        data_dir=tmp_path,
        metadata_ttl=timedelta(seconds=-1),
        minimum_age=timedelta(days=14),
    )
    database = Database(tmp_path / "wheelguard.db")
    store = FileArtifactStore(tmp_path / "artifacts")

    def online_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=wheel, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(online_handler)) as upstream:
        artifacts = ArtifactService(
            database,
            store,
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
            client=upstream,
        )
        application = create_app(
            settings=settings,
            repository=OnlineRepository(digest, len(wheel)),
            database=database,
            artifact_service=artifacts,
        )
        transport = httpx.ASGITransport(app=application)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            metadata = await client.get("/simple/demo/", headers={"Accept": SIMPLE_JSON})
            artifact = await client.get(metadata.json()["files"][0]["url"])
            assert artifact.content == wheel
            assert artifact.headers["cache-control"].startswith("private,")
            assert artifact.headers["vary"] == "Authorization"
            assert artifact.headers["x-content-type-options"] == "nosniff"

    def offline_handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"cached artifact unexpectedly requested {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(offline_handler)) as upstream:
        artifacts = ArtifactService(
            database,
            store,
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
            client=upstream,
        )
        application = create_app(
            settings=settings,
            repository=OfflineRepository(),
            database=database,
            artifact_service=artifacts,
        )
        transport = httpx.ASGITransport(app=application)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=transport, base_url="http://test") as client,
        ):
            metadata = await client.get("/simple/demo/", headers={"Accept": SIMPLE_JSON})
            artifact = await client.get(metadata.json()["files"][0]["url"])

    assert metadata.headers["x-wheelguard-cache"] == "STALE"
    assert artifact.content == wheel
