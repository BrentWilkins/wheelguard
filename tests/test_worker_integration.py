"""Exercise Worker routing and trust boundaries with Cloudflare binding fakes."""

import importlib
import json
import sys
from datetime import UTC, datetime
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


class Headers(dict[str, str]):
    """Provide the case-insensitive subset of the Workers Headers API used here."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        super().__init__({key.casefold(): value for key, value in (values or {}).items()})

    def get(self, key: str, default: str | None = None) -> str | None:
        """Look up a header without case sensitivity."""
        return super().get(key.casefold(), default)


class FakeResponse:
    """Capture a Worker response without requiring the JavaScript runtime."""

    def __init__(self, body: Any = None, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.status = status
        self.headers = Headers(headers)

    @classmethod
    def from_json(
        cls,
        body: Any,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> "FakeResponse":
        """Build a response carrying a JSON-serializable body."""
        return cls(json.dumps(body), status=status, headers=headers)


class FakeRequest:
    """Represent the request surface used by Wheelguard's Worker."""

    def __init__(self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.method = method
        self.headers = Headers(headers)


class RejectingDatabase:
    """Fail if an unauthenticated route attempts any D1 operation."""

    def prepare(self, _query: str) -> Any:
        """Expose an unexpected pre-authentication database read."""
        raise AssertionError("D1 was read before repository authentication")


class Access:
    """Supply a local Cloudflare Access identity."""

    def __init__(self, audience: str) -> None:
        self.aud = audience

    async def getIdentity(self) -> Any:
        """Return the authenticated administrator identity."""
        return SimpleNamespace(email="admin@example.com")


@pytest.fixture
def worker_modules(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any]:
    """Import Worker modules behind a small CPython-compatible runtime facade."""
    workers = ModuleType("workers")
    workers.Response = FakeResponse
    workers.WorkerEntrypoint = object
    workers.fetch = None
    monkeypatch.setitem(sys.modules, "workers", workers)
    sys.modules.pop("wheelguard.cloudflare_index", None)
    sys.modules.pop("wheelguard.worker", None)
    cloudflare_index = importlib.import_module("wheelguard.cloudflare_index")
    worker = importlib.import_module("wheelguard.worker")
    return worker, cloudflare_index


def _edge_env(**overrides: Any) -> Any:
    values = {
        "WHEELGUARD_UPSTREAM_URL": "https://pypi.org/simple/",
        "WHEELGUARD_MINIMUM_AGE_DAYS": "14",
        "WHEELGUARD_FALLBACK_MINIMUM_AGE_HOURS": "24",
        "WHEELGUARD_ALLOW_MISSING_UPLOAD_TIME": "true",
        "WHEELGUARD_METADATA_TTL_SECONDS": "300",
        "WHEELGUARD_MAXIMUM_METADATA_BYTES": "1900000",
        "WHEELGUARD_MAXIMUM_ARTIFACT_BYTES": "104857600",
        "WHEELGUARD_ALLOWED_ARTIFACT_HOSTS": "files.pythonhosted.org",
        "WHEELGUARD_REQUIRE_AUTHENTICATION": "true",
        "WHEELGUARD_OSV_ENABLED": "true",
        "WHEELGUARD_OSV_URL": "https://api.osv.dev/v1/querybatch",
        "WHEELGUARD_ADVISORY_TTL_SECONDS": "3600",
        "WHEELGUARD_ADVISORY_ACTIVE_DAYS": "30",
        "WHEELGUARD_AUTH_TOKEN": "t" * 32,
        "WHEELGUARD_DB": RejectingDatabase(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.anyio
async def test_repository_authentication_happens_before_d1(worker_modules: tuple[Any, Any]) -> None:
    """Reject a missing token without leaking request activity into D1."""
    _, cloudflare_index = worker_modules
    repository = cloudflare_index.CloudflareRepository(_edge_env())
    response = await repository.fetch(FakeRequest("https://wheelguard.example/simple/"))
    assert response.status == 401
    assert response.headers["vary"] == "Authorization"


@pytest.mark.anyio
async def test_cached_edge_artifact_is_private_and_varies_on_auth(
    worker_modules: tuple[Any, Any],
) -> None:
    """Prevent shared caches from replaying an authenticated artifact."""
    _, cloudflare_index = worker_modules

    class Bucket:
        async def get(self, _key: str) -> Any:
            return SimpleNamespace(size=8, httpEtag='"etag"', body=b"artifact")

    repository = cloudflare_index.CloudflareRepository(_edge_env(WHEELGUARD_ARTIFACTS=Bucket()))
    response = await repository._artifact(
        FakeRequest("https://wheelguard.example/files/sha256/" + "a" * 64 + "/demo.whl"),
        "/files/sha256/" + "a" * 64 + "/demo.whl",
    )
    assert response.headers["cache-control"].startswith("private,")
    assert response.headers["vary"] == "Authorization"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.anyio
async def test_admin_access_audience_and_csrf_are_enforced(worker_modules: tuple[Any, Any]) -> None:
    """Require the expected Access audience and same-origin browser writes."""
    worker, _ = worker_modules
    application = worker.Default()
    application.env = _edge_env(WHEELGUARD_ACCESS_AUD="wheelguard-admin")
    application.ctx = SimpleNamespace(access=Access("wrong-audience"))
    assert (await application.fetch(FakeRequest("https://wheelguard.example/admin"))).status == 403

    application.ctx = SimpleNamespace(access=Access("wheelguard-admin"))
    page = await application.fetch(FakeRequest("https://wheelguard.example/admin"))
    assert page.status == 200
    assert page.headers["x-content-type-options"] == "nosniff"

    rejected = await application.fetch(FakeRequest("https://wheelguard.example/admin/api/overrides", method="POST"))
    assert rejected.status == 403
    assert (
        worker._reject_cross_origin_write(
            FakeRequest(
                "https://wheelguard.example/admin/api/overrides",
                method="POST",
                headers={"Origin": "https://wheelguard.example"},
            )
        )
        is None
    )
    cross_origin = worker._reject_cross_origin_write(
        FakeRequest(
            "https://wheelguard.example/admin/api/overrides",
            method="POST",
            headers={"Origin": "https://attacker.example"},
        )
    )
    assert cross_origin is not None
    assert cross_origin.status == 403


@pytest.mark.anyio
async def test_health_route_remains_public(worker_modules: tuple[Any, Any]) -> None:
    """Keep the health probe independent from repository and administrator credentials."""
    worker, _ = worker_modules
    application = worker.Default()
    application.env = _edge_env()
    application.ctx = SimpleNamespace(access=None)
    response = await application.fetch(FakeRequest("https://wheelguard.example/healthz"))
    assert response.status == 200


@pytest.mark.anyio
async def test_vulnerability_fallback_is_visible_in_headers_and_logs(
    worker_modules: tuple[Any, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Make automatic fixed-release exceptions observable to operators and clients."""
    _, cloudflare_index = worker_modules
    settings = cloudflare_index.EdgeSettings.from_env(_edge_env())
    repository = cloudflare_index.CloudflareRepository.__new__(cloudflare_index.CloudflareRepository)
    repository._settings = settings
    payload = {
        "files": [
            {"filename": "demo-1.0.tar.gz", "upload-time": "2026-01-01T00:00:00Z"},
            {"filename": "demo-2.0.tar.gz", "upload-time": "2026-08-30T00:00:00Z"},
        ]
    }

    async def cached(_project: str) -> tuple[dict[str, Any], None, datetime]:
        return payload, None, datetime.now(UTC)

    async def record(_project: str, _now: datetime) -> None:
        return None

    async def advisories(
        _project: str, current: dict[str, Any], *, now: datetime
    ) -> tuple[dict[str, Any], str, dict[str, list[str]]]:
        return current, "HIT", {"1.0": ["GHSA-test"], "2.0": []}

    async def overrides(_project: str, _now: datetime) -> dict[str, str]:
        return {}

    async def rewrite(_request: Any, current: dict[str, Any]) -> dict[str, Any]:
        return current

    repository._cached_project = cached
    repository._record_advisory_target = record
    repository._evaluate_advisories = advisories
    repository._active_overrides = overrides
    repository._register_and_rewrite = rewrite
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(cloudflare_index, "_log", lambda event, **fields: events.append((event, fields)))

    response = await repository._project(
        FakeRequest(
            "https://wheelguard.example/simple/demo/",
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        ),
        "demo",
    )
    assert "vulnerability-fallback" in response.headers["x-wheelguard-policy"]
    assert events == [("policy.vulnerability_fallback", {"project": "demo", "versions": ["2.0"]})]
