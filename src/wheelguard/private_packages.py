"""Publish and serve private distributions independently of upstream caches."""

import asyncio
import json
from datetime import UTC, datetime
from http import HTTPMethod
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from uuid import uuid4

from workers import Response, fetch

from wheelguard.auth import TokenAuthenticator
from wheelguard.cloudflare_index import _body_response, _error, _json_response, _log, _python, _timestamp
from wheelguard.distributions import validate_distribution
from wheelguard.project_metadata import project_links
from wheelguard.simple_api import SIMPLE_JSON, negotiate_content_type, render_project_html
from wheelguard.upload_form import UploadError, receive_upload


class PrivatePackages:
    """Coordinate private name ownership, verified objects, and release policy."""

    def __init__(self, repository: Any) -> None:
        """Share the repository's bindings and runtime policy settings."""
        self.repository = repository
        self.env = repository._env
        self.db = self.env.WHEELGUARD_DB

    @property
    def bucket(self) -> Any:
        """Access object storage only for operations that need bytes."""
        return self.env.WHEELGUARD_ARTIFACTS

    async def project(self, name: str) -> dict[str, Any] | None:
        """Look up a private name, including pending collision approvals."""
        row = _python(
            await self.db.prepare("SELECT * FROM private_projects WHERE normalized_name = ?1").bind(name).first()
        )
        return row if isinstance(row, dict) else None

    async def owns(self, name: str) -> bool:
        """Report whether a successful upload has claimed this name."""
        row = await self.project(name)
        return bool(row and row.get("claimed_at"))

    async def _claimable(self, name: str, origin: str) -> None:
        row = await self.project(name)
        if row and (row.get("claimed_at") or row.get("approved_at")):
            return
        if row and json.loads(row["collisions"]):
            raise self._collision(name, origin)
        urls = list(
            dict.fromkeys(
                [
                    f"https://pypi.org/simple/{quote(name)}/",
                    urljoin(self.repository._settings.upstream_url, f"{quote(name)}/"),
                ]
            )
        )
        collisions = []
        for url in urls:
            try:
                response = await asyncio.wait_for(fetch(url, method=HTTPMethod.HEAD, redirect="manual"), timeout=15)
            except Exception as error:
                raise UploadError("Cannot check public package ownership; retry publishing later", 503) from error
            if response.status == 200:
                target = urlsplit(url)
                collisions.append(urlunsplit((target.scheme, target.netloc.rsplit("@", 1)[-1], target.path, "", "")))
            elif response.status != 404:
                raise UploadError("Public package ownership check was inconclusive; retry publishing later", 503)
        await (
            self.db.prepare("""
            INSERT INTO private_projects (normalized_name, collisions) VALUES (?1, ?2)
            ON CONFLICT(normalized_name) DO UPDATE SET collisions = excluded.collisions
            WHERE private_projects.claimed_at IS NULL AND private_projects.approved_at IS NULL
                AND private_projects.collisions = '[]'
        """)
            .bind(name, json.dumps(collisions))
            .run()
        )
        row = await self.project(name)
        if row and not row.get("claimed_at") and not row.get("approved_at") and json.loads(row["collisions"]):
            raise self._collision(name, origin)

    @staticmethod
    def _collision(name: str, origin: str) -> UploadError:
        return UploadError(
            f"Public package '{name}' already exists. Private ownership hides all upstream releases for this name. "
            f"An administrator must acknowledge this at {origin}/admin/#private-packages, then retry publishing.",
            409,
        )

    async def upload(self, request: Any) -> Response:
        """Authenticate a publisher, verify bytes, and atomically expose the file."""
        if request.method != "POST":
            return _error("Method not allowed", 405, {"Allow": "POST"})
        token = getattr(self.env, "WHEELGUARD_UPLOAD_TOKEN", None)
        if not token:
            return _error("Private publishing is disabled", 503)
        try:
            authenticator = TokenAuthenticator(str(token))
        except ValueError:
            return _error("Upload token configuration is invalid", 503)
        if not authenticator.authorize(request.headers.get("authorization")):
            return _error(
                "Publisher authentication required", 401, {"WWW-Authenticate": 'Basic realm="wheelguard-upload"'}
            )
        await self.repository._load_runtime_settings()
        key = f"private/{uuid4()}"
        completed = False
        commit_attempted = False
        discard = True
        try:
            form = await receive_upload(request, self.bucket, key, self.repository._settings.maximum_artifact_bytes)
            completed = True
            metadata = await validate_distribution(self.bucket, key, form)
            name, version, requires_python = metadata.name, metadata.version, metadata.requires_python
            repository_url, changelog_url = project_links(form.fields)
            target = urlsplit(request.url)
            await self._claimable(name, f"{target.scheme}://{target.netloc}")
            now = _timestamp(datetime.now(UTC))
            digest = form.hash.hexdigest()
            commit_attempted = True
            statements = [
                self.db.prepare("""
                    INSERT INTO private_artifacts
                        (project, filename, version, sha256, size, object_key, requires_python, uploaded_at)
                    SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
                    FROM private_projects WHERE normalized_name = ?1
                        AND (collisions = '[]' OR approved_at IS NOT NULL OR claimed_at IS NOT NULL)
                    ON CONFLICT(project, filename) DO NOTHING
                """).bind(name, form.filename, version, digest, form.size, key, requires_python, now),
                self.db.prepare("""
                    UPDATE private_projects SET claimed_at = ?2
                    WHERE normalized_name = ?1 AND claimed_at IS NULL
                        AND EXISTS (SELECT 1 FROM private_artifacts WHERE project = ?1)
                """).bind(name, now),
                self.db.prepare("""
                    UPDATE private_projects
                    SET repository_url = COALESCE(?2, repository_url),
                        changelog_url = COALESCE(?3, changelog_url)
                    WHERE normalized_name = ?1
                        AND EXISTS (
                            SELECT 1 FROM private_artifacts
                            WHERE project = ?1 AND filename = ?4 AND sha256 = ?5
                        )
                """).bind(name, repository_url, changelog_url, form.filename, digest),
            ]
            if metadata.changelog is not None:
                statements.append(
                    self.db.prepare("""
                    INSERT INTO private_changelogs (project, version, content, format, updated_at, updated_by)
                    SELECT ?1, ?2, ?3, ?4, ?5, 'publisher'
                    WHERE EXISTS (
                        SELECT 1 FROM private_artifacts
                        WHERE project = ?1 AND filename = ?6 AND sha256 = ?7
                    )
                    ON CONFLICT(project, version) DO UPDATE SET
                        content = excluded.content,
                        format = excluded.format,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                """).bind(
                        name,
                        version,
                        metadata.changelog.content,
                        metadata.changelog.format,
                        now,
                        form.filename,
                        digest,
                    )
                )
            statements.append(
                self.db.prepare("""
                    INSERT INTO policy_audit (id, event_type, actor, occurred_at, details)
                    SELECT ?1, 'private.uploaded', 'publisher', ?2, ?3
                    WHERE EXISTS (SELECT 1 FROM private_artifacts WHERE object_key = ?4)
                """).bind(
                    str(uuid4()),
                    now,
                    json.dumps({"project": name, "filename": form.filename, "sha256": digest}),
                    key,
                )
            )
            await self.db.batch(statements)
            saved = _python(
                await self.db.prepare(
                    "SELECT sha256, object_key FROM private_artifacts WHERE project = ?1 AND filename = ?2"
                )
                .bind(name, form.filename)
                .first()
            )
            if not isinstance(saved, dict):
                commit_attempted = False
                raise self._collision(name, f"{target.scheme}://{target.netloc}")
            discard = saved["object_key"] != key
            commit_attempted = False
            if saved["sha256"] != digest:
                raise UploadError("This filename already exists with different bytes; publish a new version", 409)
            return Response.from_json(
                {"project": name, "filename": form.filename, "sha256": digest}, headers={"Cache-Control": "no-store"}
            )
        except UploadError as error:
            return _error(str(error), error.status)
        except Exception as error:
            _log(
                "private.upload.error",
                error_type=type(error).__name__,
                object_key=key,
                commit_uncertain=commit_attempted,
            )
            return _error("Private publication could not be completed; retry the same file", 503)
        finally:
            # A lost D1 response may follow a successful commit. Retain that
            # unique object rather than risk deleting bytes that were published.
            if completed and discard and not commit_attempted:
                await self.bucket.delete(key)

    async def listing(self, request: Any, name: str) -> Response:
        """Render only private releases, without public age or OSV evaluation."""
        media_type = negotiate_content_type(request.headers.get("accept"))
        if media_type is None:
            return _error("No supported Simple API representation was requested", 406)
        rows = _python(
            await self.db.prepare("""
            SELECT filename, version, sha256, size, requires_python, uploaded_at
            FROM private_artifacts WHERE project = ?1 ORDER BY filename
        """)
            .bind(name)
            .raw()
        )
        overrides = await self.repository._active_overrides(name, datetime.now(UTC))
        files = []
        versions = set()
        for filename, version, digest, size, requires_python, uploaded_at in rows:
            if overrides.get(version) == "block":
                continue
            files.append(
                {
                    "filename": filename,
                    "url": urljoin(request.url, f"/files/private/sha256/{digest}/{quote(filename)}"),
                    "hashes": {"sha256": digest},
                    "size": size,
                    "requires-python": requires_python,
                    "upload-time": uploaded_at,
                }
            )
            versions.add(version)
        payload = {"meta": {"api-version": "1.4"}, "name": name, "files": files, "versions": sorted(versions)}
        headers = {
            "Content-Type": media_type,
            "Cache-Control": "private, no-store",
            "Vary": "Accept, Authorization",
            "X-Wheelguard-Policy": "private, administrator-overrides",
            "X-Wheelguard-Advisories": "PRIVATE",
        }
        if media_type == SIMPLE_JSON:
            return _json_response(payload, request, headers)
        return _body_response(render_project_html(payload), request, headers)

    async def artifact(self, request: Any, digest: str, filename: str) -> Response:
        """Serve private bytes only after checking current administrator policy."""
        row = _python(
            await self.db.prepare("""
            SELECT a.* FROM private_artifacts a JOIN private_projects p ON p.normalized_name = a.project
            WHERE sha256 = ?1 AND filename = ?2 AND p.claimed_at IS NOT NULL
        """)
            .bind(digest, filename)
            .first()
        )
        if not isinstance(row, dict):
            return _error("Artifact not found", 404)
        actions = await self.repository._active_overrides(row["project"], datetime.now(UTC))
        if actions.get(row["version"]) == "block":
            return _error("Artifact denied by administrator policy block", 403)
        stored = await self.bucket.get(row["object_key"])
        if stored is None:
            return _error("Private artifact is unavailable; no upstream fallback is permitted", 503)
        return _body_response(
            stored.body,
            request,
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(row["size"]),
                "Cache-Control": "private, no-store",
                "Vary": "Authorization",
                "ETag": f'"sha256:{digest}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
