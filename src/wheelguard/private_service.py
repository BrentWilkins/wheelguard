"""Cloud-neutral private package publication and resolution."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from fastapi import Request
from packaging.version import Version

from wheelguard.azure_storage import AzureBlobBucket, upload_request_adapter
from wheelguard.distributions import validate_distribution
from wheelguard.identity import GitLabOidcValidator, PublisherIdentity, authorization_token
from wheelguard.project_metadata import project_links
from wheelguard.upload_form import UploadError, receive_upload


class PrivatePackageService:
    """Coordinate PostgreSQL ownership with immutable Blob objects."""

    def __init__(
        self,
        database: Any,
        bucket: AzureBlobBucket,
        publisher: GitLabOidcValidator,
        *,
        upstream_url: str,
        maximum_bytes: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._database = database
        self._bucket = bucket
        self._publisher = publisher
        self._upstream_url = upstream_url
        self._maximum_bytes = maximum_bytes
        self._client = client or httpx.AsyncClient(follow_redirects=False, timeout=15)
        self._owns_client = client is None

    async def authenticate(self, request: Request) -> PublisherIdentity:
        return await self._publisher.validate(authorization_token(request.headers.get("authorization")))

    def configure_maximum_bytes(self, maximum_bytes: int) -> None:
        self._maximum_bytes = maximum_bytes

    async def upload(self, request: Request, identity: PublisherIdentity) -> dict[str, str]:
        key = f"private/{uuid4()}"
        completed, commit_attempted, discard = False, False, True
        try:
            form = await receive_upload(upload_request_adapter(request), self._bucket, key, self._maximum_bytes)
            completed = True
            metadata = await validate_distribution(self._bucket, key, form)
            name, version, requires_python = metadata.name, metadata.version, metadata.requires_python
            repository_url, changelog_url = project_links(form.fields)
            await self._claimable(name, str(request.base_url).rstrip("/"))
            digest = form.hash.hexdigest()
            commit_attempted = True
            saved = await self._database.publish_private_artifact(
                project=name,
                filename=form.filename,
                version=version,
                sha256=digest,
                size=form.size,
                object_key=key,
                requires_python=requires_python,
                repository_url=repository_url,
                changelog_url=changelog_url,
                changelog=metadata.changelog.content if metadata.changelog else None,
                changelog_format=metadata.changelog.format if metadata.changelog else None,
                uploaded_at=datetime.now(UTC),
                actor=f"gitlab:{identity.project_path}:{identity.subject}",
            )
            if saved is None:
                commit_attempted = False
                raise self._collision(name, str(request.base_url).rstrip("/"))
            discard = saved["object_key"] != key
            commit_attempted = False
            if saved["sha256"] != digest:
                raise UploadError("This filename already exists with different bytes; publish a new version", 409)
            return {"project": name, "filename": form.filename, "sha256": digest}
        finally:
            if completed and discard and not commit_attempted:
                await self._bucket.delete(key)

    async def owns(self, name: str) -> bool:
        row = await self._database.private_project(name)
        return bool(row and row.get("claimed_at"))

    async def catalog(self) -> list[tuple[str, str]]:
        """Return claimed private projects with their newest published version."""
        newest: dict[str, Version] = {}
        for row in await self._database.private_project_versions():
            name, version = row["normalized_name"], Version(row["version"])
            if name not in newest or version > newest[name]:
                newest[name] = version
        return [(name, str(newest[name])) for name in sorted(newest)]

    async def details(self, name: str) -> dict[str, object] | None:
        """Return non-sensitive catalog details for a claimed project."""
        row = await self._database.private_project(name)
        if row is None or row.get("claimed_at") is None:
            return None
        version = next((version for project, version in await self.catalog() if project == name), None)
        if version is None:
            return None
        changelog = await self._database.private_changelog(name, version)
        return {
            "name": name,
            "version": version,
            "repository_url": row.get("repository_url"),
            "changelog_url": row.get("changelog_url"),
            "changelog": changelog,
        }

    async def listing(self, project: str, base_url: str) -> dict[str, object]:
        rows = await self._database.private_artifacts(project)
        overrides = await self._database.active_overrides(project, datetime.now(UTC))
        files, versions = [], set()
        for row in rows:
            if overrides.get(row["version"]) == "block":
                continue
            files.append(
                {
                    "filename": row["filename"],
                    "url": urljoin(base_url, f"/files/private/sha256/{row['sha256']}/{quote(row['filename'])}"),
                    "hashes": {"sha256": row["sha256"]},
                    "size": row["size"],
                    "requires-python": row["requires_python"],
                    "upload-time": row["uploaded_at"].isoformat().replace("+00:00", "Z"),
                }
            )
            versions.add(row["version"])
        return {"meta": {"api-version": "1.4"}, "name": project, "files": files, "versions": sorted(versions)}

    async def artifact(self, digest: str, filename: str) -> tuple[object, dict[str, object]] | None:
        row = await self._database.private_artifact(digest, filename)
        if row is None:
            return None
        if (await self._database.active_overrides(row["project"], datetime.now(UTC))).get(row["version"]) == "block":
            raise PermissionError("Artifact denied by administrator policy block")
        stored = await self._bucket.get(row["object_key"])
        return None if stored is None else (stored, row)

    async def _claimable(self, name: str, origin: str) -> None:
        row = await self._database.private_project(name)
        if row and (row.get("claimed_at") or row.get("approved_at")):
            return
        if row and row["collisions"]:
            raise self._collision(name, origin)
        urls = list(
            dict.fromkeys([f"https://pypi.org/simple/{quote(name)}/", urljoin(self._upstream_url, f"{quote(name)}/")])
        )
        collisions = []
        for url in urls:
            try:
                response = await asyncio.wait_for(self._client.head(url), timeout=15)
            except (httpx.HTTPError, TimeoutError) as error:
                raise UploadError("Cannot check public package ownership; retry publishing later", 503) from error
            if response.status_code == 200:
                target = urlsplit(url)
                collisions.append(urlunsplit((target.scheme, target.netloc.rsplit("@", 1)[-1], target.path, "", "")))
            elif response.status_code != 404:
                raise UploadError("Public package ownership check was inconclusive; retry publishing later", 503)
        row = await self._database.record_private_collisions(name, collisions)
        if not row.get("claimed_at") and not row.get("approved_at") and row["collisions"]:
            raise self._collision(name, origin)

    @staticmethod
    def _collision(name: str, origin: str) -> UploadError:
        return UploadError(
            f"Public package '{name}' already exists. An administrator must acknowledge private ownership at "
            f"{origin}/admin/#private-packages, then retry publishing.",
            409,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
        await self._publisher.aclose()
