from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from wheelguard.application import create_app
from wheelguard.config import Settings
from wheelguard.models import AdvisoryResult, ProjectRepository, ProjectResponse, SimplePayload, UpstreamNotFoundError
from wheelguard.simple_api import SIMPLE_HTML, SIMPLE_JSON


class FakeRepository:
    async def get_project(self, normalized_name: str) -> ProjectResponse:
        assert normalized_name == "demo-package"
        return ProjectResponse(
            {
                "meta": {"api-version": "1.4", "extension": "kept"},
                "name": normalized_name,
                "versions": ["1.0", "2.0"],
                "files": [
                    {
                        "filename": "demo_package-1.0-py3-none-any.whl",
                        "url": "https://files.example/old.whl",
                        "hashes": {"sha256": "a" * 64},
                        "upload-time": "2026-08-01T00:00:00Z",
                        "unknown": {"kept": True},
                    },
                    {
                        "filename": "demo_package-2.0-py3-none-any.whl",
                        "url": "https://files.example/new.whl",
                        "upload-time": "2026-08-25T00:00:00Z",
                    },
                ],
            },
            "12345",
        )


class MissingRepository:
    async def get_project(self, normalized_name: str) -> ProjectResponse:
        raise UpstreamNotFoundError(normalized_name)


class VulnerableOldRelease:
    """Mark the normally eligible release as vulnerable."""

    async def apply(self, project: str, payload: SimplePayload) -> AdvisoryResult:
        """Add the same advisory markers as the OSV policy."""
        assert project == "demo-package"
        result = {**payload, "files": [dict(file) for file in payload["files"]]}
        result["files"][0]["yanked"] = "Wheelguard advisories: GHSA-test"
        result["files"][0]["wheelguard-advisories"] = ["GHSA-test"]
        return AdvisoryResult(result, "HIT", vulnerable_files=1)


def make_app(repository: ProjectRepository, data_dir: Path) -> FastAPI:
    return create_app(
        settings=Settings(
            minimum_age=timedelta(days=14),
            data_dir=data_dir,
            allowed_artifact_hosts=frozenset({"files.example"}),
        ),
        repository=repository,
        clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_json_filters_new_files_and_preserves_extensions(tmp_path: Path) -> None:
    application = make_app(FakeRepository(), tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        response = await client.get("/simple/demo-package/", headers={"Accept": SIMPLE_JSON})
        root = await client.get("/simple/", headers={"Accept": SIMPLE_JSON})
    assert response.status_code == 200
    assert response.headers["x-pypi-last-serial"] == "12345"
    assert response.headers["x-wheelguard-hidden-files"] == "1"
    assert response.headers["vary"] == "Accept, Authorization"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.json()["meta"]["extension"] == "kept"
    assert len(response.json()["files"]) == 1
    assert "/files/sha256/" in response.json()["files"][0]["url"]
    assert root.json()["projects"] == [{"name": "demo-package"}]


@pytest.mark.anyio
async def test_html_and_normalization_redirect(tmp_path: Path) -> None:
    application = make_app(FakeRepository(), tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        html = await client.get("/simple/demo-package/", headers={"Accept": SIMPLE_HTML})
        redirect = await client.get("/simple/Demo_Package/", follow_redirects=False)
    assert html.status_code == 200
    assert "demo_package-1.0" in html.text
    assert "demo_package-2.0" not in html.text
    assert redirect.status_code == 308
    assert redirect.headers["location"].endswith("/simple/demo-package/")


@pytest.mark.anyio
async def test_missing_project_is_404(tmp_path: Path) -> None:
    application = make_app(MissingRepository(), tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        response = await client.get("/simple/missing/", headers={"Accept": SIMPLE_JSON})
        assert response.status_code == 404


@pytest.mark.anyio
async def test_authentication_protects_repository_but_not_health(tmp_path: Path) -> None:
    application = create_app(
        settings=Settings(data_dir=tmp_path, auth_token="s" * 32),
        repository=FakeRepository(),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client:
        denied = await client.get("/simple/demo-package/")
        health = await client.get("/healthz")

    assert denied.status_code == 401
    assert denied.headers["WWW-Authenticate"] == 'Basic realm="Wheelguard"'
    assert health.status_code == 200


@pytest.mark.anyio
async def test_self_hosted_fallback_respects_floor_and_reports_use(tmp_path: Path) -> None:
    """Use the bounded fixed release fallback on the self-hosted serving path."""
    application = create_app(
        settings=Settings(
            data_dir=tmp_path,
            minimum_age=timedelta(days=14),
            fallback_minimum_age=timedelta(days=1),
            allowed_artifact_hosts=frozenset({"files.example"}),
        ),
        repository=FakeRepository(),
        advisory_policy=VulnerableOldRelease(),
        clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client,
    ):
        response = await client.get("/simple/demo-package/", headers={"Accept": SIMPLE_JSON})
    assert response.status_code == 200
    filenames = {file["filename"] for file in response.json()["files"]}
    assert "demo_package-2.0-py3-none-any.whl" in filenames
    assert response.headers["x-wheelguard-policy"] == "minimum-age, vulnerability-fallback"
