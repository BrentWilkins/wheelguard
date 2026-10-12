"""Regression coverage for locked-install advisory preflight."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import httpx
import pytest

from wheelguard.advisories import OsvAdvisoryPolicy
from wheelguard.application import _selected_versions, create_app
from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.config import Settings
from wheelguard.database import Database
from wheelguard.models import ProjectResponse
from wheelguard.simple_api import SIMPLE_JSON


class Repository:
    """Serve one controlled project and record deduplicated requests."""

    def __init__(self, digest: str) -> None:
        self.digest = digest
        self.requests = 0

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        self.requests += 1
        assert normalized_name == "demo-package"
        return ProjectResponse(
            {
                "name": normalized_name,
                "files": [
                    {
                        "filename": "demo_package-1.0-py3-none-any.whl",
                        "url": "https://files.example/demo.whl",
                        "hashes": {"sha256": self.digest},
                        "upload-time": "2026-08-01T00:00:00Z",
                    }
                ],
            }
        )


class BulkRepository:
    """Serve distinct controlled projects with measurable bounded latency."""

    def __init__(self) -> None:
        self.requests = 0
        self.active = 0
        self.maximum_active = 0

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        self.requests += 1
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        try:
            await asyncio.sleep(0.02)
        finally:
            self.active -= 1
        digest = hashlib.sha256(normalized_name.encode()).hexdigest()
        return ProjectResponse(
            {
                "name": normalized_name,
                "files": [
                    {
                        "filename": f"{normalized_name.replace('-', '_')}-1.0-py3-none-any.whl",
                        "url": f"https://files.example/{normalized_name}.whl",
                        "hashes": {"sha256": digest},
                        "upload-time": "2026-08-01T00:00:00Z",
                    }
                ],
            }
        )


def anyio_backend() -> str:
    return "asyncio"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        minimum_age=timedelta(0),
        allowed_artifact_hosts=frozenset({"files.example"}),
        osv_enabled=True,
        osv_url="https://osv.example/v1/querybatch",
        advisory_ttl=timedelta(days=30),
        auth_token="s" * 32,
    )


def test_selected_versions_retain_only_locked_artifacts() -> None:
    payload = {
        "name": "demo-package",
        "meta": {"api-version": "1.4"},
        "files": [
            {"filename": "demo_package-1.0-py3-none-any.whl"},
            {"filename": "demo_package-2.0.tar.gz"},
            {"filename": "unparseable"},
        ],
    }

    selected = _selected_versions(payload, {"2.0"})

    assert selected == {
        "name": "demo-package",
        "meta": {"api-version": "1.4"},
        "files": [{"filename": "demo_package-2.0.tar.gz"}],
    }
    assert len(payload["files"]) == 3


@pytest.mark.anyio
async def test_preflight_refreshes_registers_and_allows_artifact(tmp_path: Path) -> None:
    content = b"trusted wheel"
    digest = hashlib.sha256(content).hexdigest()
    current = datetime.now(UTC)
    database = Database(tmp_path / "wheelguard.db")
    repository = Repository(digest)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "osv.example":
            return httpx.Response(200, json={"results": [{}]}, request=request)
        return httpx.Response(200, content=content, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        policy = OsvAdvisoryPolicy(
            database,
            url="https://osv.example/v1/querybatch",
            ttl=timedelta(days=30),
            client=client,
            clock=lambda: current,
        )
        artifacts = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
            client=client,
        )
        application = create_app(
            settings=_settings(tmp_path),
            repository=repository,
            database=database,
            advisory_policy=policy,
            artifact_service=artifacts,
            clock=lambda: current,
        )
        auth = httpx.BasicAuth("wheelguard", "s" * 32)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://packages.test") as api,
        ):
            response = await api.post(
                "/preflight",
                auth=auth,
                json={
                    "projects": [
                        {"name": "Demo_Package", "versions": ["1.0", "1.0"]},
                        {"name": "demo-package", "versions": ["1.0"]},
                    ]
                },
            )
            artifact = await api.get(
                f"/files/sha256/{digest}/demo_package-1.0-py3-none-any.whl",
                auth=auth,
            )

    assert response.status_code == 200
    assert response.json()["status"] == "READY"
    assert response.json()["projects"] == [
        {"project": "demo-package", "status": "READY", "advisories": "MISS", "versions": ["1.0"]}
    ]
    assert repository.requests == 1
    assert artifact.status_code == 200
    assert artifact.content == content


@pytest.mark.anyio
async def test_preflight_refreshes_advisories_before_their_cached_ttl_expires(tmp_path: Path) -> None:
    """Do not attest an install with an advisory result that may expire mid-sync."""
    content = b"trusted wheel"
    digest = hashlib.sha256(content).hexdigest()
    database = Database(tmp_path / "wheelguard.db")
    repository = Repository(digest)
    osv_requests = 0
    checked_at = [datetime(2026, 9, 1, tzinfo=UTC)]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal osv_requests
        if request.url.host == "osv.example":
            osv_requests += 1
            return httpx.Response(200, json={"results": [{}]}, request=request)
        return httpx.Response(200, content=content, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        policy = OsvAdvisoryPolicy(
            database,
            url="https://osv.example/v1/querybatch",
            ttl=timedelta(days=30),
            client=client,
            clock=lambda: checked_at[0],
        )
        await database.initialize()
        cached = await policy.apply("demo-package", (await repository.get_project("demo-package")).payload)
        assert cached.status == "MISS"
        checked_at[0] = datetime(2026, 9, 30, 23, 50, tzinfo=UTC)

        application = create_app(
            settings=_settings(tmp_path),
            repository=repository,
            database=database,
            advisory_policy=policy,
        )
        auth = httpx.BasicAuth("wheelguard", "s" * 32)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://packages.test") as api,
        ):
            response = await api.post(
                "/preflight",
                auth=auth,
                json={"projects": [{"name": "demo-package", "versions": ["1.0"]}]},
            )

    assert response.status_code == 200
    assert response.json()["projects"][0]["advisories"] == "MISS"
    assert osv_requests == 2


@pytest.mark.anyio
async def test_bulk_preflight_is_bounded_and_warm_repeat_uses_caches(tmp_path: Path) -> None:
    """Exercise cold and warm 86-project requests without serial upstream work."""
    database = Database(tmp_path / "wheelguard.db")
    repository = BulkRepository()
    osv_requests = 0
    osv_active = 0
    maximum_osv_active = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal maximum_osv_active, osv_active, osv_requests
        assert request.url.host == "osv.example"
        osv_requests += 1
        osv_active += 1
        maximum_osv_active = max(maximum_osv_active, osv_active)
        try:
            await asyncio.sleep(0.02)
        finally:
            osv_active -= 1
        queries = request.read().count(b'"ecosystem"')
        return httpx.Response(200, json={"results": [{} for _ in range(queries)]}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        policy = OsvAdvisoryPolicy(
            database,
            url="https://osv.example/v1/querybatch",
            ttl=timedelta(days=30),
            client=client,
            clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
        )
        application = create_app(
            settings=_settings(tmp_path),
            repository=repository,
            database=database,
            advisory_policy=policy,
            clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
        )
        auth = httpx.BasicAuth("wheelguard", "s" * 32)
        projects = [{"name": f"project-{index:03d}", "versions": ["1.0"]} for index in range(86)]
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://packages.test") as api,
        ):
            started = perf_counter()
            cold = await api.post("/preflight", auth=auth, json={"projects": projects})
            cold_seconds = perf_counter() - started
            started = perf_counter()
            warm = await api.post("/preflight", auth=auth, json={"projects": projects})
            warm_seconds = perf_counter() - started

    assert cold.status_code == warm.status_code == 200
    assert len(cold.json()["projects"]) == len(warm.json()["projects"]) == 86
    assert {result["advisories"] for result in cold.json()["projects"]} == {"MISS"}
    assert {result["advisories"] for result in warm.json()["projects"]} == {"HIT"}
    assert repository.requests == osv_requests == 86
    assert 1 < repository.maximum_active <= 8
    assert 1 < maximum_osv_active <= 8
    assert warm_seconds < cold_seconds


@pytest.mark.anyio
async def test_unavailable_advisories_return_no_usable_simple_response(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"trusted wheel").hexdigest()
    database = Database(tmp_path / "wheelguard.db")

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("OSV unavailable", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
        policy = OsvAdvisoryPolicy(
            database, url="https://osv.example/v1/querybatch", ttl=timedelta(days=30), client=client
        )
        application = create_app(
            settings=_settings(tmp_path),
            repository=Repository(digest),
            database=database,
            advisory_policy=policy,
        )
        auth = httpx.BasicAuth("wheelguard", "s" * 32)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://packages.test") as api,
        ):
            simple = await api.get("/simple/demo-package/", auth=auth, headers={"Accept": SIMPLE_JSON})
            preflight = await api.post(
                "/preflight",
                auth=auth,
                json={"projects": [{"name": "demo-package", "versions": ["1.0"]}]},
            )
            artifact = await api.get(
                f"/files/sha256/{digest}/demo_package-1.0-py3-none-any.whl",
                auth=auth,
            )

    assert simple.status_code == 503
    assert simple.headers["x-wheelguard-policy"] == "advisory-unavailable"
    assert "/files/" not in simple.text
    assert preflight.status_code == 503
    assert preflight.json()["status"] == "UNAVAILABLE"
    assert artifact.status_code == 403
    assert artifact.headers["x-wheelguard-policy"] == "artifact-denied"


@pytest.mark.anyio
async def test_vulnerable_locked_version_remains_denied_after_preflight(tmp_path: Path) -> None:
    digest = hashlib.sha256(b"trusted wheel").hexdigest()
    database = Database(tmp_path / "wheelguard.db")

    def vulnerable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test"}]}]}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(vulnerable)) as client:
        policy = OsvAdvisoryPolicy(
            database, url="https://osv.example/v1/querybatch", ttl=timedelta(days=30), client=client
        )
        application = create_app(
            settings=_settings(tmp_path),
            repository=Repository(digest),
            database=database,
            advisory_policy=policy,
        )
        auth = httpx.BasicAuth("wheelguard", "s" * 32)
        async with (
            application.router.lifespan_context(application),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://packages.test") as api,
        ):
            preflight = await api.post(
                "/preflight",
                auth=auth,
                json={"projects": [{"name": "demo-package", "versions": ["1.0"]}]},
            )
            artifact = await api.get(
                f"/files/sha256/{digest}/demo_package-1.0-py3-none-any.whl",
                auth=auth,
            )

    assert preflight.status_code == 409
    assert preflight.json()["projects"][0]["status"] == "VULNERABLE"
    assert artifact.status_code == 403
    assert "GHSA-test" in artifact.text
