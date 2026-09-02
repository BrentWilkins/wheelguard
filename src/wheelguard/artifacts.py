"""Cache and serve verified Python distribution artifacts."""

import asyncio
import hashlib
import os
import re
import tempfile
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import httpx

from wheelguard.database import Database
from wheelguard.models import (
    ArtifactDownloadError,
    ArtifactNotFoundError,
    ArtifactRecord,
    SimplePayload,
)

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
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
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the artifact service and its optional HTTP client."""
        self._database = database
        self._store = store
        self._maximum_bytes = maximum_bytes
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(follow_redirects=True, timeout=60.0)
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def rewrite_urls(self, payload: SimplePayload, *, url_for: ArtifactUrl) -> SimplePayload:
        """Register upstream artifacts and rewrite cacheable URLs."""
        await self._database.register_artifacts(payload)
        result = deepcopy(payload)
        files = result.get("files", [])
        if not isinstance(files, list):
            return result
        for file in files:
            if not isinstance(file, dict):
                continue
            digest = _sha256(file)
            filename = file.get("filename")
            if digest is not None and isinstance(filename, str) and _safe_filename(filename):
                file["url"] = url_for(digest, filename)
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
        if record.size is not None and record.size > self._maximum_bytes:
            raise ArtifactDownloadError("Artifact exceeds the configured size limit")
        self._store.root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="wheelguard-", suffix=".part", dir=self._store.root)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                async with self._client.stream("GET", record.source_url) as response:
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


def _sha256(file: dict[str, Any]) -> str | None:
    hashes = file.get("hashes")
    digest = hashes.get("sha256") if isinstance(hashes, dict) else None
    if not isinstance(digest, str):
        return None
    digest = digest.casefold()
    return digest if SHA256_PATTERN.fullmatch(digest) else None


def _safe_filename(filename: str) -> bool:
    return bool(filename) and Path(filename).name == filename
