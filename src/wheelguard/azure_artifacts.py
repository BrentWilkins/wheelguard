"""Cache verified public artifacts in Azure Blob Storage."""

from __future__ import annotations

import asyncio
import hashlib
import weakref
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urljoin

import httpx
from azure.core.exceptions import AzureError

from wheelguard.artifacts import (
    MAXIMUM_REDIRECTS,
    REDIRECT_STATUSES,
    SHA256_PATTERN,
    ArtifactUrl,
    _allowed_https_url,
    _safe_filename,
    _sha256,
)
from wheelguard.azure_storage import AzureBlobBucket, AzureObject
from wheelguard.models import (
    ArtifactDownloadError,
    ArtifactNotFoundError,
    ArtifactPolicyDeniedError,
    ArtifactRecord,
    SimplePayload,
)


class AzureArtifactService:
    """Rewrite, fetch, verify, and serve artifacts through one Blob container."""

    def __init__(
        self,
        database: Any,
        bucket: AzureBlobBucket,
        *,
        maximum_bytes: int,
        allowed_hosts: frozenset[str],
        enforce_advisories: bool,
        advisory_ttl: timedelta,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._database = database
        self._bucket = bucket
        self._maximum_bytes = maximum_bytes
        self._allowed_hosts = allowed_hosts
        self._enforce_advisories = enforce_advisories
        self._advisory_ttl = advisory_ttl
        self._client = client or httpx.AsyncClient(follow_redirects=False, timeout=60)
        self._owns_client = client is None
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = weakref.WeakValueDictionary()

    async def rewrite_urls(self, project: str, payload: SimplePayload, *, url_for: ArtifactUrl) -> SimplePayload:
        result = deepcopy(payload)
        registered: list[dict[str, Any]] = []
        visible: list[Any] = []
        files = result.get("files", [])
        if not isinstance(files, list):
            return result
        for file in files:
            if not isinstance(file, dict):
                continue
            digest, filename, source_url = _sha256(file), file.get("filename"), file.get("url")
            if (
                digest is not None
                and isinstance(filename, str)
                and _safe_filename(filename)
                and isinstance(source_url, str)
                and _allowed_https_url(source_url, self._allowed_hosts)
            ):
                registered.append(deepcopy(file))
                file["url"] = url_for(digest, filename)
                visible.append(file)
        result["files"] = visible
        await self._database.register_artifacts(project, {"files": registered})
        return result

    def configure_policy(
        self, *, enforce_advisories: bool, advisory_ttl: timedelta, maximum_bytes: int | None = None
    ) -> None:
        """Apply administrator-editable policy values for the next request."""
        self._enforce_advisories = enforce_advisories
        self._advisory_ttl = advisory_ttl
        if maximum_bytes is not None:
            self._maximum_bytes = maximum_bytes

    async def get_stream(self, digest: str, filename: str) -> AzureObject:
        digest = digest.casefold()
        if SHA256_PATTERN.fullmatch(digest) is None or not _safe_filename(filename):
            raise ArtifactNotFoundError(filename)
        record = await self._database.get_artifact(digest, filename)
        if record is None:
            raise ArtifactNotFoundError(filename)
        action = None
        if record.project is not None and record.version is not None:
            private = await self._database.private_project(record.project)
            if private is not None and private.get("claimed_at") is not None:
                raise ArtifactPolicyDeniedError("Upstream artifact denied because this name is privately owned")
            action = (await self._database.active_overrides(record.project, datetime.now(UTC))).get(record.version)
        if action == "block":
            raise ArtifactPolicyDeniedError("Artifact denied by administrator policy block")
        if self._enforce_advisories and action != "allow":
            await self._authorize(record)
        key = _key(record)
        stored = await self._bucket.get(key)
        if stored is not None:
            return stored
        lock = self._locks.setdefault((digest, filename), asyncio.Lock())
        async with lock:
            stored = await self._bucket.get(key)
            if stored is None:
                await self._download(record, key)
                stored = await self._bucket.get(key)
            if stored is None:
                raise ArtifactDownloadError("Verified Blob artifact is unavailable")
            return stored

    async def _authorize(self, record: ArtifactRecord) -> None:
        if record.project is None or record.version is None:
            raise ArtifactPolicyDeniedError("Artifact has no policy identity; refresh project metadata")
        cached = await self._database.get_latest_advisories(record.project)
        if cached is None or record.version not in cached.advisories:
            raise ArtifactPolicyDeniedError("Artifact has no current advisory evaluation")
        if datetime.now(UTC) - cached.checked_at >= self._advisory_ttl:
            raise ArtifactPolicyDeniedError("Artifact advisory evaluation is stale; refresh project metadata")
        if identifiers := cached.advisories[record.version]:
            raise ArtifactPolicyDeniedError(f"Artifact denied by Wheelguard advisories: {', '.join(identifiers)}")

    async def _download(self, record: ArtifactRecord, key: str) -> None:
        if not _allowed_https_url(record.source_url, self._allowed_hosts):
            raise ArtifactDownloadError("Artifact source is not allowed")
        upload = await self._bucket.createMultipartUpload(key)
        parts: list[Any] = []
        digest, size = hashlib.sha256(), 0
        try:
            response = await self._allowed_response(record.source_url)
            try:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(5 * 1024 * 1024):
                    size += len(chunk)
                    if size > self._maximum_bytes:
                        raise ArtifactDownloadError("Artifact exceeds the configured size limit")
                    digest.update(chunk)
                    parts.append(await upload.uploadPart(len(parts) + 1, chunk))
            finally:
                await response.aclose()
            if digest.hexdigest() != (record.verification_sha256 or record.sha256):
                raise ArtifactDownloadError("Artifact SHA-256 does not match upstream metadata")
            await upload.complete(parts)
        except ArtifactDownloadError:
            await upload.abort()
            raise
        except (AzureError, httpx.HTTPError) as error:
            await upload.abort()
            raise ArtifactDownloadError("Artifact download or Blob write failed") from error

    async def _allowed_response(self, url: str) -> httpx.Response:
        current = url
        for redirect_count in range(MAXIMUM_REDIRECTS + 1):
            if not _allowed_https_url(current, self._allowed_hosts):
                raise ArtifactDownloadError("Artifact redirect target is not allowed")
            response = await self._client.send(self._client.build_request("GET", current), stream=True)
            if response.status_code not in REDIRECT_STATUSES:
                return response
            location = response.headers.get("location")
            await response.aclose()
            if location is None or redirect_count == MAXIMUM_REDIRECTS:
                raise ArtifactDownloadError("Artifact exceeded redirect limit")
            current = urljoin(current, location)
        raise ArtifactDownloadError("Artifact exceeded redirect limit")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def _key(record: ArtifactRecord) -> str:
    return f"public/sha256/{record.sha256[:2]}/{record.sha256[2:4]}/{record.sha256}/{record.filename}"
