from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from wheelguard.advisories import OsvAdvisoryPolicy
from wheelguard.database import Database


def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_yanks_vulnerable_versions_and_reuses_cached_scan(tmp_path: Path) -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        body = request.read().decode()
        assert '"ecosystem":"PyPI"' in body
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-test-0001"}]},
                    {},
                ]
            },
        )

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    policy = OsvAdvisoryPolicy(
        database,
        url="https://osv.example/querybatch",
        ttl=timedelta(hours=1),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    payload = {
        "name": "demo",
        "files": [
            {"filename": "demo-1.0-py3-none-any.whl", "url": "https://example/1.0"},
            {"filename": "demo-2.0.tar.gz", "url": "https://example/2.0"},
        ],
    }

    first = await policy.apply("demo", payload)
    second = await policy.apply("demo", payload)

    assert first.status == "MISS"
    assert first.vulnerable_files == 1
    assert first.payload["files"][0]["yanked"] == "Wheelguard advisories: GHSA-test-0001"
    assert first.payload["files"][0]["wheelguard-advisories"] == ["GHSA-test-0001"]
    assert "yanked" not in first.payload["files"][1]
    assert "yanked" not in payload["files"][0]
    assert second.status == "HIT"
    assert requests == 1
    await policy.aclose()


@pytest.mark.anyio
async def test_uses_stale_advisories_when_osv_is_unavailable(tmp_path: Path) -> None:
    current = datetime(2026, 1, 1, tzinfo=UTC)
    offline = False

    def handler(request: httpx.Request) -> httpx.Response:
        if offline:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "PYSEC-1"}]}]})

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    policy = OsvAdvisoryPolicy(
        database,
        url="https://osv.example/querybatch",
        ttl=timedelta(minutes=5),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        clock=lambda: current,
    )
    payload = {"files": [{"filename": "demo-1.0.tar.gz"}]}

    await policy.apply("demo", payload)
    current += timedelta(minutes=6)
    offline = True
    result = await policy.apply("demo", payload)

    assert result.status == "STALE"
    assert result.vulnerable_files == 1
    assert result.payload["files"][0]["yanked"] == "Wheelguard advisories: PYSEC-1"
    await policy.aclose()


@pytest.mark.anyio
async def test_fails_open_without_a_cached_scan(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    policy = OsvAdvisoryPolicy(
        database,
        url="https://osv.example/querybatch",
        ttl=timedelta(hours=1),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    payload = {"files": [{"filename": "demo-1.0.tar.gz"}]}

    result = await policy.apply("demo", payload)

    assert result.status == "ERROR"
    assert result.payload is payload
    await policy.aclose()
