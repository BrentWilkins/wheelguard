from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from wheelguard.application import _render_landing_page, _render_package_page, create_app
from wheelguard.config import Settings
from wheelguard.database import Database
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
                        "core-metadata": {"sha256": "c" * 64},
                        "upload-time": "2026-08-01T00:00:00Z",
                        "unknown": {"kept": True},
                    },
                    {
                        "filename": "demo_package-2.0-py3-none-any.whl",
                        "url": "https://files.example/new.whl",
                        "hashes": {"sha256": "b" * 64},
                        "upload-time": "2026-08-25T00:00:00Z",
                    },
                ],
            },
            "12345",
        )


class MissingRepository:
    async def get_project(self, normalized_name: str) -> ProjectResponse:
        raise UpstreamNotFoundError(normalized_name)


class ManagedTokenDatabase(Database):
    """Exercise database-backed repository authentication."""

    def __init__(self, path: Path, token: str) -> None:
        super().__init__(path)
        self.token = token
        self.authentication_attempts = 0

    async def authenticate_repository_token(self, token: str) -> bool:
        self.authentication_attempts += 1
        return token == self.token


class AdminDatabase(Database):
    """Record administrator writes without requiring PostgreSQL in a route test."""

    actor: str | None = None

    async def settings(self) -> dict[str, str]:
        return {}

    async def update_settings(self, updates: dict[str, int | bool], actor: str, occurred_at: datetime) -> None:
        assert updates == {"minimum_age_days": 10}
        assert occurred_at.tzinfo is not None
        self.actor = actor


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
            public_url="https://packages.example",
        ),
        repository=repository,
        clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
    )


def test_landing_page_lists_internal_packages_and_current_versions() -> None:
    landing = _render_landing_page(
        [("private-flight", "2.1"), ("escaped-name", "1.0")],
        public_origin="https://packages.example",
        documentation_url="https://docs.example/wheelguard/",
    )

    assert '<li><a href="/packages/private-flight/">private-flight</a><span>2.1</span></li>' in landing
    assert '<li><a href="/packages/escaped-name/">escaped-name</a><span>1.0</span></li>' in landing
    assert "https://packages.example/simple/" in landing
    assert "https://docs.example/wheelguard/" in landing


def test_package_page_links_changelog_and_explains_private_gitlab_access() -> None:
    page = _render_package_page(
        {
            "name": "private-flight",
            "version": "2.1",
            "repository_url": "https://gitlab.example/acx/flight",
            "changelog_url": "https://gitlab.example/acx/flight/-/blob/main/CHANGELOG.md",
        },
        "private-flight",
    )

    assert "Latest version: <strong>2.1</strong>" in page
    assert "Open changelog" in page
    assert "may require additional repository access" in page


def test_package_page_handles_missing_changelog() -> None:
    page = _render_package_page(
        {"name": "private-flight", "version": "2.1", "repository_url": None, "changelog_url": None},
        "private-flight",
    )

    assert "No changelog link has been published yet." in page


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
    assert response.json()["files"][0]["url"].startswith("https://packages.example/files/sha256/")
    assert response.json()["files"][0]["core-metadata"] == {"sha256": "c" * 64}


@pytest.mark.anyio
async def test_html_and_normalization_redirect(tmp_path: Path) -> None:
    application = make_app(FakeRepository(), tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        html = await client.get("/simple/demo-package/", headers={"Accept": SIMPLE_HTML})
        browser = await client.get(
            "/simple/demo-package/", headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        )
        redirect = await client.get("/simple/Demo_Package/", follow_redirects=False)
    assert html.status_code == 200
    assert "demo_package-1.0" in html.text
    assert "demo_package-2.0" not in html.text
    assert html.headers["content-type"].startswith(SIMPLE_HTML)
    assert browser.headers["content-type"].startswith("text/html")
    assert "Links for demo-package" in browser.text
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
        landing = await client.get("/")

    assert denied.status_code == 401
    assert denied.headers["WWW-Authenticate"] == 'Basic realm="Wheelguard"'
    assert health.status_code == 200
    assert landing.status_code == 200
    assert "A policy-aware, outage-resistant path" in landing.text
    assert "http://test/simple/" in landing.text
    assert landing.headers["x-content-type-options"] == "nosniff"


@pytest.mark.anyio
async def test_admin_token_is_separate_and_records_actor(tmp_path: Path) -> None:
    admin_token = "a" * 32
    repository_token = "r" * 32
    database = AdminDatabase(tmp_path / "admin.db")
    application = create_app(
        settings=Settings(
            data_dir=tmp_path,
            database_url="host=postgres.invalid dbname=wheelguard",
            admin_token=admin_token,
            admin_token_actor="brent",
            auth_token=repository_token,
        ),
        repository=FakeRepository(),
        database=database,
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://wheelguard.test") as client,
    ):
        denied = await client.get("/admin/")
        login_page = await client.get("/admin/login")
        repository_denied = await client.get("/admin/", auth=httpx.BasicAuth("package", repository_token))
        invalid = await client.post(
            "/admin/login",
            headers={"Origin": "https://wheelguard.test"},
            data={"username": "brent", "password": "wrong"},
        )
        logged_in = await client.post(
            "/admin/login",
            headers={"Origin": "https://wheelguard.test"},
            data={"username": "brent", "password": admin_token},
        )
        session_allowed = await client.get("/admin/")
        basic_allowed = await client.get("/admin/", auth=httpx.BasicAuth("brent", admin_token))
        updated = await client.patch(
            "/admin/api/settings",
            headers={"Origin": "https://wheelguard.test"},
            json={"minimum_age_days": 10},
        )
        logged_out = await client.post("/admin/logout", headers={"Origin": "https://wheelguard.test"})
        denied_again = await client.get("/admin/")

    assert denied.status_code == 303
    assert denied.headers["location"] == "/admin/login"
    assert login_page.status_code == 200
    assert 'autocomplete="username"' in login_page.text
    assert 'autocomplete="current-password"' in login_page.text
    assert invalid.status_code == 401
    assert "Invalid username or password" in invalid.text
    assert logged_in.status_code == 303
    assert "wheelguard_admin_session=" in logged_in.headers["set-cookie"]
    assert "HttpOnly" in logged_in.headers["set-cookie"]
    assert "SameSite=strict" in logged_in.headers["set-cookie"]
    assert "Secure" in logged_in.headers["set-cookie"]
    assert session_allowed.status_code == 200
    assert repository_denied.status_code == 401
    assert basic_allowed.status_code == 200
    assert "Signed in as <strong>brent</strong>" in session_allowed.text
    assert updated.status_code == 200
    assert logged_out.status_code == 303
    assert denied_again.status_code == 303
    assert database.actor == "brent"


@pytest.mark.anyio
async def test_admin_login_uses_configured_public_origin_behind_proxy(tmp_path: Path) -> None:
    application = create_app(
        settings=Settings(
            data_dir=tmp_path,
            database_url="host=postgres.invalid dbname=wheelguard",
            public_url="https://packages.example",
            admin_token="a" * 32,
            admin_token_actor="brent",
        ),
        repository=FakeRepository(),
        database=AdminDatabase(tmp_path / "proxy-admin.db"),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://internal-container"
    ) as client:
        response = await client.post(
            "/admin/login",
            headers={"Origin": "https://packages.example"},
            data={"username": "brent", "password": "a" * 32},
        )

    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]


@pytest.mark.anyio
async def test_managed_repository_token_authentication(tmp_path: Path) -> None:
    token = "wg_" + "s" * 43
    database = ManagedTokenDatabase(tmp_path / "managed.db", token)
    application = create_app(
        settings=Settings(data_dir=tmp_path, managed_token_auth_enabled=True),
        repository=FakeRepository(),
        database=database,
    )
    basic = httpx.BasicAuth("brent", token)
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client,
    ):
        denied = await client.get("/simple/demo-package/")
        allowed = await client.get("/simple/demo-package/", auth=basic)
        health = await client.get("/healthz")

    assert denied.status_code == 401
    assert allowed.status_code == 200
    assert health.status_code == 200
    assert database.authentication_attempts == 1


@pytest.mark.anyio
async def test_managed_tokens_do_not_override_private_ingress_default(tmp_path: Path) -> None:
    database = ManagedTokenDatabase(tmp_path / "managed-disabled.db", "wg_" + "s" * 43)
    application = create_app(
        settings=Settings(data_dir=tmp_path),
        repository=FakeRepository(),
        database=database,
    )
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://test") as client,
    ):
        response = await client.get("/simple/demo-package/")

    assert response.status_code == 200
    assert database.authentication_attempts == 0


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
