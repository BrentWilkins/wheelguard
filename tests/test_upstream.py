import httpx
import pytest

from wheelguard.models import UpstreamNotFoundError
from wheelguard.upstream import PyPIRepository


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_fetches_json_and_resolves_relative_links() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept"] == "application/vnd.pypi.simple.v1+json"
        return httpx.Response(
            200,
            request=request,
            headers={"X-PyPI-Last-Serial": "42"},
            json={
                "meta": {"api-version": "1.4"},
                "name": "demo",
                "files": [
                    {
                        "filename": "demo-1.0.tar.gz",
                        "url": "../../files/demo-1.0.tar.gz",
                        "provenance": "../../files/demo-1.0.tar.gz.provenance",
                    }
                ],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = PyPIRepository("https://index.example/simple/", client=client)
        result = await repository.get_project("demo")

    assert result.last_serial == "42"
    assert result.payload["files"][0]["url"] == "https://index.example/files/demo-1.0.tar.gz"
    assert result.payload["files"][0]["provenance"].endswith(".tar.gz.provenance")


@pytest.mark.anyio
async def test_maps_upstream_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        repository = PyPIRepository("https://index.example/simple/", client=client)
        with pytest.raises(UpstreamNotFoundError):
            await repository.get_project("missing")
