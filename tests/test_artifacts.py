import hashlib
from pathlib import Path

import httpx
import pytest

from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.database import Database
from wheelguard.models import ArtifactDownloadError


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_downloads_verifies_and_reuses_artifact(tmp_path: Path) -> None:
    content = b"trusted wheel bytes"
    digest = hashlib.sha256(content).hexdigest()
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=content, request=request)

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            client=client,
        )
        payload = {
            "name": "demo",
            "files": [
                {
                    "filename": "demo-1.0-py3-none-any.whl",
                    "url": "https://files.example/demo.whl",
                    "hashes": {"sha256": digest},
                    "size": len(content),
                }
            ],
        }
        rewritten = await service.rewrite_urls(
            payload,
            url_for=lambda sha256, filename: f"/files/{sha256}/{filename}",
        )
        first = await service.get_path(digest, "demo-1.0-py3-none-any.whl")
        second = await service.get_path(digest, "demo-1.0-py3-none-any.whl")

    assert rewritten["files"][0]["url"].startswith("/files/")
    assert first.read_bytes() == content
    assert second == first
    assert requests == 1


@pytest.mark.anyio
async def test_rejects_hash_mismatch(tmp_path: Path) -> None:
    expected = hashlib.sha256(b"expected").hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"tampered", request=request)

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            client=client,
        )
        await service.rewrite_urls(
            {
                "files": [
                    {
                        "filename": "demo.whl",
                        "url": "https://files.example/demo.whl",
                        "hashes": {"sha256": expected},
                    }
                ]
            },
            url_for=lambda sha256, filename: f"/files/{sha256}/{filename}",
        )
        with pytest.raises(ArtifactDownloadError, match="SHA-256"):
            await service.get_path(expected, "demo.whl")
