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
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        service = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
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
        assert len(service._locks) == 0
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
            allowed_hosts=frozenset({"files.example"}),
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


@pytest.mark.anyio
async def test_does_not_register_or_rewrite_untrusted_artifact_hosts(tmp_path: Path) -> None:
    """Prevent upstream metadata from turning the downloader into an SSRF primitive."""
    digest = hashlib.sha256(b"artifact").hexdigest()
    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    service = ArtifactService(
        database,
        FileArtifactStore(tmp_path / "artifacts"),
        maximum_bytes=1024,
        allowed_hosts=frozenset({"files.example"}),
    )
    payload = {
        "files": [
            {
                "filename": "demo.whl",
                "url": "http://127.0.0.1/internal",
                "hashes": {"sha256": digest},
            }
        ]
    }
    rewritten = await service.rewrite_urls(payload, url_for=lambda sha256, filename: f"/{sha256}/{filename}")
    assert rewritten["files"] == []
    assert await database.get_artifact(digest, "demo.whl") is None
    await service.aclose()


@pytest.mark.anyio
async def test_rejects_redirects_to_untrusted_hosts(tmp_path: Path) -> None:
    """Revalidate the final URL after following an artifact redirect."""
    content = b"artifact"
    digest = hashlib.sha256(content).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "files.example":
            return httpx.Response(302, headers={"Location": "https://127.0.0.1/internal"}, request=request)
        return httpx.Response(200, content=content, request=request)

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        service = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
            client=client,
        )
        await service.rewrite_urls(
            {
                "files": [
                    {
                        "filename": "demo.whl",
                        "url": "https://files.example/demo.whl",
                        "hashes": {"sha256": digest},
                    }
                ]
            },
            url_for=lambda sha256, filename: f"/{sha256}/{filename}",
        )
        with pytest.raises(ArtifactDownloadError, match="redirect target"):
            await service.get_path(digest, "demo.whl")


@pytest.mark.anyio
async def test_rejects_untrusted_legacy_record_before_network_access(tmp_path: Path) -> None:
    """Protect databases populated before source URL validation was introduced."""
    digest = hashlib.sha256(b"artifact").hexdigest()
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=b"artifact", request=request)

    database = Database(tmp_path / "wheelguard.db")
    await database.initialize()
    await database.register_artifacts(
        {
            "files": [
                {
                    "filename": "demo.whl",
                    "url": "http://127.0.0.1/internal",
                    "hashes": {"sha256": digest},
                }
            ]
        }
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = ArtifactService(
            database,
            FileArtifactStore(tmp_path / "artifacts"),
            maximum_bytes=1024,
            allowed_hosts=frozenset({"files.example"}),
            client=client,
        )
        with pytest.raises(ArtifactDownloadError, match="source is not allowed"):
            await service.get_path(digest, "demo.whl")
    assert requests == 0
