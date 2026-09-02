"""Regression tests for Cloudflare artifact streaming."""

import hashlib
import importlib
import sys
from http import HTTPMethod
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests with asyncio."""
    return "asyncio"


def _cloudflare_index(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the edge module with a minimal Workers runtime facade."""
    workers = ModuleType("workers")
    workers.Response = type("Response", (), {})
    workers.fetch = None
    monkeypatch.setitem(sys.modules, "workers", workers)
    sys.modules.pop("wheelguard.cloudflare_index", None)
    return importlib.import_module("wheelguard.cloudflare_index")


@pytest.mark.anyio
async def test_metadata_sidecar_probes_missing_size_before_streaming(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use HEAD size when PEP 658 metadata has no catalog size."""
    module = _cloudflare_index(monkeypatch)
    source_url = "https://files.pythonhosted.org/packages/demo.whl.metadata"
    content = b"verified metadata"

    class BufferedBody:
        def to_bytes(self) -> bytes:
            return content

    buffered_body = BufferedBody()
    requests: list[dict[str, Any]] = []

    class GetResponse:
        status = 200
        url = source_url
        headers: dict[str, str] = {}
        body = object()

        async def buffer(self) -> Any:
            return buffered_body

    async def fake_fetch(url: str, **options: Any) -> Any:
        requests.append({"url": url, **options})
        if options.get("method") == HTTPMethod.HEAD:
            return SimpleNamespace(status=200, url=url, headers={"content-length": "5"})
        return GetResponse()

    class Bucket:
        def __init__(self) -> None:
            self.puts: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        async def put(self, *args: Any, **kwargs: Any) -> None:
            self.puts.append((args, kwargs))

    bucket = Bucket()
    repository = module.CloudflareRepository.__new__(module.CloudflareRepository)
    repository._settings = SimpleNamespace(
        allowed_artifact_hosts=frozenset({"files.pythonhosted.org"}),
        maximum_artifact_bytes=20_000,
        maximum_metadata_bytes=1_000,
    )
    repository._env = SimpleNamespace(WHEELGUARD_ARTIFACTS=bucket)
    monkeypatch.setattr(module, "fetch", fake_fetch)

    verification_hash = hashlib.sha256(content).hexdigest()
    await repository._populate_artifact(
        "sha256/demo/demo.whl.metadata",
        "demo.whl.metadata",
        {"source_url": source_url, "size": None, "verification_sha256": verification_hash},
    )

    assert requests == [
        {"url": source_url, "method": HTTPMethod.HEAD, "redirect": "manual"},
        {"url": source_url, "redirect": "manual"},
    ]
    assert bucket.puts[0][0] == ("sha256/demo/demo.whl.metadata", buffered_body)
    assert "sha256" not in bucket.puts[0][1]

    with pytest.raises(module.RepositoryError, match="SHA-256 does not match"):
        await repository._populate_artifact(
            "sha256/demo/bad.whl.metadata",
            "bad.whl.metadata",
            {"source_url": source_url, "size": None, "verification_sha256": "0" * 64},
        )
    assert len(bucket.puts) == 1


@pytest.mark.anyio
async def test_rejects_untrusted_redirect_before_worker_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not issue a Worker subrequest to an untrusted redirect target."""

    module = _cloudflare_index(monkeypatch)
    requests: list[str] = []

    async def fake_fetch(url: str, **_options: Any) -> Any:
        requests.append(url)
        return SimpleNamespace(
            status=302,
            headers={"location": "https://127.0.0.1/internal"},
            url=url,
        )

    repository = module.CloudflareRepository.__new__(module.CloudflareRepository)
    repository._settings = SimpleNamespace(allowed_artifact_hosts=frozenset({"files.pythonhosted.org"}))
    monkeypatch.setattr(module, "fetch", fake_fetch)

    with pytest.raises(module.RepositoryError, match="redirect target"):
        await repository._fetch_artifact("https://files.pythonhosted.org/packages/demo.whl")
    assert requests == ["https://files.pythonhosted.org/packages/demo.whl"]
