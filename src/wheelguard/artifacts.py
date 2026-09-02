"""Cache and serve verified Python distribution artifacts."""

import asyncio
import hashlib
import os
import re
import tempfile
import weakref
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from wheelguard.database import Database
from wheelguard.models import (
    ArtifactDownloadError,
    ArtifactNotFoundError,
    ArtifactRecord,
    SimplePayload,
)

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAXIMUM_REDIRECTS = 5
ArtifactUrl = Callable[[str, str], str]


class FileArtifactStore:
    """Store artifacts in a content-addressed directory tree."""

    def __init__(self, root: Path) -> None:
        """Initialize the store beneath ``root``."""
        self.root = root

    def path(self, record: ArtifactRecord) -> Path:
        """Return the canonical local path for an artifact record."""
        return self.root / "sha256" / record.sha256[:2] / record.sha256[2:4] / record.sha256 / record.filename

    def commit(self, temporary: Path, record: ArtifactRecord) -> Path:
        """Atomically publish a verified temporary artifact."""
        destination = self.path(record)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            temporary.unlink(missing_ok=True)
        else:
            os.replace(temporary, destination)
        return destination


class ArtifactService:
    """Rewrite artifact links and populate the verified local cache."""

    def __init__(
        self,
        database: Database,
        store: FileArtifactStore,
        *,
        maximum_bytes: int,
        allowed_hosts: frozenset[str],
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the artifact service and its optional HTTP client."""
        self._database = database
        self._store = store
        self._maximum_bytes = maximum_bytes
        self._allowed_hosts = allowed_hosts
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(follow_redirects=False, timeout=60.0)
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = weakref.WeakValueDictionary()

    async def rewrite_urls(self, payload: SimplePayload, *, url_for: ArtifactUrl) -> SimplePayload:
        """Register upstream artifacts and rewrite cacheable URLs."""
        result = deepcopy(payload)
        files = result.get("files", [])
        if not isinstance(files, list):
            return result
        registered: list[dict[str, Any]] = []
        visible: list[Any] = []
        for file in files:
            if not isinstance(file, dict):
                visible.append(file)
                continue
            digest = _sha256(file)
            filename = file.get("filename")
            source_url = file.get("url")
            if isinstance(source_url, str) and not _allowed_https_url(source_url, self._allowed_hosts):
                continue
            visible.append(file)
            if (
                digest is not None
                and isinstance(filename, str)
                and _safe_filename(filename)
                and isinstance(source_url, str)
                and _allowed_https_url(source_url, self._allowed_hosts)
            ):
                registered.append(deepcopy(file))
                file["url"] = url_for(digest, filename)
        result["files"] = visible
        await self._database.register_artifacts({"files": registered})
        return result

    async def get_path(self, digest: str, filename: str) -> Path:
        """Return a verified cached artifact, downloading it when necessary."""
        digest = digest.casefold()
        if SHA256_PATTERN.fullmatch(digest) is None or not _safe_filename(filename):
            raise ArtifactNotFoundError(filename)
        record = await self._database.get_artifact(digest, filename)
        if record is None:
            raise ArtifactNotFoundError(filename)
        cached = self._store.path(record)
        if cached.is_file():
            return cached

        key = (digest, filename)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if cached.is_file():
                return cached
            return await self._download(record)

    async def aclose(self) -> None:
        """Close the owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()

    async def _download(self, record: ArtifactRecord) -> Path:
        if not _allowed_https_url(record.source_url, self._allowed_hosts):
            raise ArtifactDownloadError("Artifact source is not allowed")
        if record.size is not None and record.size > self._maximum_bytes:
            raise ArtifactDownloadError("Artifact exceeds the configured size limit")
        self._store.root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="wheelguard-", suffix=".part", dir=self._store.root)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                async with self._stream_allowed(record.source_url) as response:
                    response.raise_for_status()
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self._maximum_bytes:
                            raise ArtifactDownloadError("Artifact exceeds the configured size limit")
                        digest.update(chunk)
                        output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if digest.hexdigest() != record.sha256:
                raise ArtifactDownloadError("Artifact SHA-256 does not match upstream metadata")
            return self._store.commit(temporary, record)
        except (httpx.HTTPError, OSError) as error:
            raise ArtifactDownloadError("Artifact download failed") from error
        finally:
            temporary.unlink(missing_ok=True)

    @asynccontextmanager
    async def _stream_allowed(self, source_url: str) -> AsyncIterator[httpx.Response]:
        """Open an artifact response after validating every redirect target."""
        current_url = source_url
        for redirect_count in range(MAXIMUM_REDIRECTS + 1):
            if not _allowed_https_url(current_url, self._allowed_hosts):
                raise ArtifactDownloadError("Artifact redirect target is not allowed")
            request = self._client.build_request("GET", current_url)
            response = await self._client.send(request, stream=True, follow_redirects=False)
            if response.status_code not in REDIRECT_STATUSES:
                try:
                    yield response
                finally:
                    await response.aclose()
                return

            location = response.headers.get("location")
            await response.aclose()
            if location is None:
                raise ArtifactDownloadError("Artifact redirect has no location")
            if redirect_count == MAXIMUM_REDIRECTS:
                raise ArtifactDownloadError("Artifact exceeded redirect limit")
            current_url = urljoin(current_url, location)

        raise ArtifactDownloadError("Artifact exceeded redirect limit")


def _sha256(file: dict[str, Any]) -> str | None:
    hashes = file.get("hashes")
    digest = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(digest, str):
        return None
    digest = digest.casefold()
    return digest if SHA256_PATTERN.fullmatch(digest) else None


def _safe_filename(filename: str) -> bool:
    return bool(filename) and Path(filename).name == filename


def _allowed_https_url(url: str, allowed_hosts: frozenset[str]) -> bool:
    """Return whether an artifact URL is HTTPS on an explicitly allowed host."""
    try:
        target = urlsplit(url)
        port = target.port
    except ValueError:
        return False
    return (
        target.scheme == "https"
        and target.hostname is not None
        and target.hostname.casefold() in allowed_hosts
        and port in {None, 443}
        and target.username is None
        and target.password is None
    )
