"""Serve the Python Simple API from Cloudflare D1 and R2 bindings."""

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from http import HTTPMethod
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from packaging.utils import canonicalize_name
from workers import Response, fetch

from wheelguard.auth import TokenAuthenticator
from wheelguard.models import SimplePayload
from wheelguard.policy import ReleasePolicy
from wheelguard.runtime_settings import decode_stored_settings
from wheelguard.simple_api import (
    SIMPLE_JSON,
    negotiate_content_type,
    render_project_html,
    render_root_html,
)
from wheelguard.vulnerabilities import (
    InvalidOsvResponseError,
    apply_advisories,
    automatic_fixed_version_allows,
    parse_osv_results,
    payload_versions,
    versions_key,
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UPSTREAM_ACCEPT = "application/vnd.pypi.simple.v1+json"


class RepositoryError(Exception):
    """Indicate that repository metadata or an artifact could not be served safely."""


class ProjectNotFoundError(RepositoryError):
    """Indicate that the upstream repository does not contain a project."""


@dataclass(frozen=True, slots=True)
class EdgeSettings:
    """Hold validated Cloudflare repository settings."""

    upstream_url: str
    minimum_age: timedelta
    metadata_ttl: timedelta
    maximum_metadata_bytes: int
    maximum_artifact_bytes: int
    allowed_artifact_hosts: frozenset[str]
    require_authentication: bool
    osv_enabled: bool
    osv_url: str
    advisory_ttl: timedelta
    advisory_active_window: timedelta

    def editable_values(self) -> dict[str, int | bool]:
        """Return the administrator-editable subset as primitive values."""
        return {
            "minimum_age_days": self.minimum_age.days,
            "metadata_ttl_seconds": int(self.metadata_ttl.total_seconds()),
            "maximum_artifact_bytes": self.maximum_artifact_bytes,
            "osv_enabled": self.osv_enabled,
            "advisory_ttl_seconds": int(self.advisory_ttl.total_seconds()),
            "advisory_active_days": self.advisory_active_window.days,
        }

    def with_runtime_overrides(self, values: dict[str, int | bool]) -> "EdgeSettings":
        """Return settings with validated D1 policy overrides applied."""
        return replace(
            self,
            minimum_age=timedelta(days=_integer_value(values, "minimum_age_days", self.minimum_age.days)),
            metadata_ttl=timedelta(
                seconds=_integer_value(values, "metadata_ttl_seconds", int(self.metadata_ttl.total_seconds()))
            ),
            maximum_artifact_bytes=_integer_value(values, "maximum_artifact_bytes", self.maximum_artifact_bytes),
            osv_enabled=_boolean_value(values, "osv_enabled", self.osv_enabled),
            advisory_ttl=timedelta(
                seconds=_integer_value(values, "advisory_ttl_seconds", int(self.advisory_ttl.total_seconds()))
            ),
            advisory_active_window=timedelta(
                days=_integer_value(values, "advisory_active_days", self.advisory_active_window.days)
            ),
        )

    @classmethod
    def from_env(cls, env: Any) -> "EdgeSettings":
        """Load edge settings from Worker variables."""
        upstream_url = str(env.WHEELGUARD_UPSTREAM_URL)
        parsed = urlsplit(upstream_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise RepositoryError("WHEELGUARD_UPSTREAM_URL must be an HTTPS URL")
        hosts = frozenset(
            host.strip().casefold() for host in str(env.WHEELGUARD_ALLOWED_ARTIFACT_HOSTS).split(",") if host.strip()
        )
        if not hosts:
            raise RepositoryError("WHEELGUARD_ALLOWED_ARTIFACT_HOSTS cannot be empty")
        osv_url = str(env.WHEELGUARD_OSV_URL)
        osv_target = urlsplit(osv_url)
        if osv_target.scheme != "https" or not osv_target.netloc:
            raise RepositoryError("WHEELGUARD_OSV_URL must be an HTTPS URL")
        return cls(
            upstream_url=upstream_url.rstrip("/") + "/",
            minimum_age=timedelta(days=_positive_int(env.WHEELGUARD_MINIMUM_AGE_DAYS, "minimum age")),
            metadata_ttl=timedelta(seconds=_positive_int(env.WHEELGUARD_METADATA_TTL_SECONDS, "metadata TTL")),
            maximum_metadata_bytes=_positive_int(env.WHEELGUARD_MAXIMUM_METADATA_BYTES, "metadata limit"),
            maximum_artifact_bytes=_positive_int(env.WHEELGUARD_MAXIMUM_ARTIFACT_BYTES, "artifact limit"),
            allowed_artifact_hosts=hosts,
            require_authentication=_boolean(env.WHEELGUARD_REQUIRE_AUTHENTICATION),
            osv_enabled=_boolean(env.WHEELGUARD_OSV_ENABLED),
            osv_url=osv_url,
            advisory_ttl=timedelta(seconds=_positive_int(env.WHEELGUARD_ADVISORY_TTL_SECONDS, "advisory TTL")),
            advisory_active_window=timedelta(
                days=_positive_int(env.WHEELGUARD_ADVISORY_ACTIVE_DAYS, "advisory active window")
            ),
        )


class CloudflareRepository:
    """Handle authenticated Simple API and artifact requests using bound storage."""

    def __init__(self, env: Any) -> None:
        """Bind a repository handler to one Worker environment."""
        self._env = env
        self._settings = EdgeSettings.from_env(env)
        token = getattr(env, "WHEELGUARD_AUTH_TOKEN", None)
        self._authenticator = TokenAuthenticator(str(token) if token is not None else None)

    async def fetch(self, request: Any) -> Response:
        """Route one repository request."""
        await self._load_runtime_settings()
        if self._settings.require_authentication and not self._authenticator.enabled:
            return _error("Repository authentication is required but WHEELGUARD_AUTH_TOKEN is not configured", 503)
        if not self._authenticator.authorize(request.headers.get("authorization")):
            return _error(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="wheelguard", charset="UTF-8"'},
            )
        path = urlsplit(request.url).path
        if request.method not in {"GET", "HEAD"}:
            return _error("Method not allowed", 405, {"Allow": "GET, HEAD"})
        if path == "/simple":
            return _redirect(_with_trailing_slash(request.url))
        if path == "/simple/":
            return await self._root(request)
        if path.startswith("/simple/"):
            if not path.endswith("/"):
                return _redirect(_with_trailing_slash(request.url))
            project = unquote(path.removeprefix("/simple/").removesuffix("/"))
            if not project or "/" in project:
                return _error("Project not found", 404)
            return await self._project(request, canonicalize_name(project))
        if path.startswith("/files/sha256/"):
            return await self._artifact(request, path)
        return _error("Not found", 404)

    async def _load_runtime_settings(self) -> None:
        """Apply valid D1 settings while retaining deployment defaults on read failure."""
        try:
            raw = await self._env.WHEELGUARD_DB.prepare("SELECT key, value FROM settings").raw()
        except Exception as error:
            _log("settings.read.error", error=str(error))
            return
        self._settings = self._settings.with_runtime_overrides(decode_stored_settings(_python(raw)))

    async def _root(self, request: Any) -> Response:
        """List projects that have been requested and cached."""
        media_type = negotiate_content_type(request.headers.get("accept"))
        if media_type is None:
            return _error("No acceptable Simple API representation", 406)
        raw = await self._env.WHEELGUARD_DB.prepare(
            "SELECT normalized_name FROM projects ORDER BY normalized_name"
        ).raw()
        projects = [str(row[0]) for row in _python(raw) if row]
        headers = _simple_headers(media_type, "D1")
        if media_type == SIMPLE_JSON:
            payload = {
                "meta": {"api-version": "1.4"},
                "projects": [{"name": project} for project in projects],
            }
            return _json_response(payload, request, headers)
        return _body_response(render_root_html(projects), request, headers)

    async def _project(self, request: Any, project: str) -> Response:
        """Fetch, filter, register, and render one project's metadata."""
        media_type = negotiate_content_type(request.headers.get("accept"))
        if media_type is None:
            return _error("No acceptable Simple API representation", 406)
        cached = await self._cached_project(project)
        now = datetime.now(UTC)
        cache_status = "HIT"
        if cached is None or now - cached[2] > self._settings.metadata_ttl:
            try:
                payload, last_serial = await self._fetch_upstream_project(project)
                await self._store_project(project, payload, last_serial, now)
                cache_status = "MISS" if cached is None else "REFRESH"
            except ProjectNotFoundError:
                return _error("Project not found", 404)
            except RepositoryError as error:
                if cached is None:
                    return _error(str(error), 502)
                payload, last_serial, _ = cached
                cache_status = "STALE"
                _log("metadata.stale", project=project, error=str(error))
        else:
            payload, last_serial, _ = cached
        await self._record_advisory_target(project, now)
        payload, advisory_status, advisories = await self._evaluate_advisories(project, payload, now=now)
        automatic_allows = automatic_fixed_version_allows(
            payload,
            advisories,
            now=now,
            minimum_age=self._settings.minimum_age,
        )
        overrides = await self._active_overrides(project, now)
        automatic_allows.update(overrides)
        result = ReleasePolicy(self._settings.minimum_age).apply(payload, now=now, overrides=automatic_allows)
        rewritten = await self._register_and_rewrite(request, result.payload)
        headers = _simple_headers(media_type, cache_status)
        headers["X-Wheelguard-Advisories"] = advisory_status
        headers["X-Wheelguard-Hidden-Files"] = str(result.hidden_files)
        if last_serial:
            headers["X-PyPI-Last-Serial"] = last_serial
        if media_type == SIMPLE_JSON:
            return _json_response(rewritten, request, headers)
        return _body_response(render_project_html(rewritten), request, headers)

    async def _cached_project(self, project: str) -> tuple[SimplePayload, str | None, datetime] | None:
        """Read a cached upstream project document from D1."""
        row = _python(
            await self._env.WHEELGUARD_DB.prepare(
                "SELECT payload, last_serial, fetched_at FROM projects WHERE normalized_name = ?1"
            )
            .bind(project)
            .first()
        )
        if not isinstance(row, dict):
            return None
        try:
            payload = json.loads(str(row["payload"]))
            fetched_at = _datetime(str(row["fetched_at"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        serial = row.get("last_serial")
        return payload, str(serial) if serial is not None else None, fetched_at

    async def _fetch_upstream_project(self, project: str) -> tuple[SimplePayload, str | None]:
        """Retrieve bounded PEP 691 metadata from the configured upstream."""
        url = urljoin(self._settings.upstream_url, f"{quote(project, safe='')}/")
        try:
            response = await fetch(url, headers={"Accept": _UPSTREAM_ACCEPT})
        except Exception as error:
            raise RepositoryError("Upstream metadata request failed") from error
        if response.status == 404:
            raise ProjectNotFoundError
        if not 200 <= response.status < 300:
            raise RepositoryError(f"Upstream metadata returned HTTP {response.status}")
        declared_size = _content_length(response.headers.get("content-length"))
        if declared_size is not None and declared_size > self._settings.maximum_metadata_bytes:
            raise RepositoryError("Upstream metadata exceeds the configured size limit")
        raw = await response.text()
        if len(raw.encode("utf-8")) > self._settings.maximum_metadata_bytes:
            raise RepositoryError("Upstream metadata exceeds the configured size limit")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RepositoryError("Upstream returned invalid JSON metadata") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
            raise RepositoryError("Upstream returned an invalid Simple API document")
        last_serial = response.headers.get("x-pypi-last-serial")
        return payload, str(last_serial) if last_serial else None

    async def _store_project(
        self,
        project: str,
        payload: SimplePayload,
        last_serial: str | None,
        fetched_at: datetime,
    ) -> None:
        """Upsert an upstream project document in D1."""
        await (
            self._env.WHEELGUARD_DB.prepare(
                """
            INSERT INTO projects (normalized_name, payload, last_serial, fetched_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(normalized_name) DO UPDATE SET
                payload = excluded.payload,
                last_serial = excluded.last_serial,
                fetched_at = excluded.fetched_at
            """
            )
            .bind(project, json.dumps(payload, separators=(",", ":")), last_serial, _timestamp(fetched_at))
            .run()
        )

    async def _active_overrides(self, project: str, now: datetime) -> dict[str, str]:
        """Return the newest active action for every overridden project version."""
        raw = (
            await self._env.WHEELGUARD_DB.prepare(
                """
            SELECT version, action
            FROM policy_overrides
            WHERE project = ?1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?2)
            ORDER BY created_at DESC
            """
            )
            .bind(project, _timestamp(now))
            .raw()
        )
        actions: dict[str, str] = {}
        for row in _python(raw):
            if len(row) >= 2:
                actions.setdefault(str(row[0]), str(row[1]))
        return actions

    async def _record_advisory_target(self, project: str, requested_at: datetime) -> None:
        """Remember that a project is actively used and should receive periodic scans."""
        if not self._settings.osv_enabled:
            return
        await (
            self._env.WHEELGUARD_DB.prepare(
                """
            INSERT INTO advisory_targets (project, requested_at)
            VALUES (?1, ?2)
            ON CONFLICT(project) DO UPDATE SET requested_at = excluded.requested_at
            """
            )
            .bind(project, _timestamp(requested_at))
            .run()
        )

    async def _evaluate_advisories(
        self,
        project: str,
        payload: SimplePayload,
        *,
        now: datetime,
        force: bool = False,
    ) -> tuple[SimplePayload, str, dict[str, list[str]]]:
        """Apply a fresh, cached, or stale OSV scan to project metadata."""
        if not self._settings.osv_enabled:
            return payload, "DISABLED", {}
        versions = payload_versions(payload)
        if not versions:
            return payload, "EMPTY", {}
        key = versions_key(versions)
        cached = await self._cached_advisories(project, key)
        if not force and cached is not None and now - cached[1] <= self._settings.advisory_ttl:
            return apply_advisories(payload, cached[0]), "HIT", cached[0]
        try:
            advisories = await self._query_osv(project, versions)
            await self._store_advisories(project, key, advisories, now)
        except RepositoryError as error:
            if cached is None:
                _log("advisory.error", project=project, error=str(error))
                return payload, "ERROR", {}
            _log("advisory.stale", project=project, error=str(error))
            return apply_advisories(payload, cached[0]), "STALE", cached[0]
        return apply_advisories(payload, advisories), "MISS" if not force else "REFRESH", advisories

    async def _cached_advisories(self, project: str, key: str) -> tuple[dict[str, list[str]], datetime] | None:
        """Read a version-set-specific advisory scan from D1."""
        row = _python(
            await self._env.WHEELGUARD_DB.prepare(
                """
                SELECT payload, checked_at
                FROM advisory_scans
                WHERE project = ?1 AND versions_key = ?2
                """
            )
            .bind(project, key)
            .first()
        )
        if not isinstance(row, dict):
            return None
        try:
            raw = json.loads(str(row["payload"]))
            checked_at = _datetime(str(row["checked_at"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        advisories = _advisory_mapping(raw)
        return (advisories, checked_at) if advisories is not None else None

    async def _query_osv(self, project: str, versions: list[str]) -> dict[str, list[str]]:
        """Query OSV in bounded batches for every version represented by a project."""
        advisories: dict[str, list[str]] = {}
        for start in range(0, len(versions), 500):
            batch = versions[start : start + 500]
            body = {
                "queries": [
                    {"package": {"ecosystem": "PyPI", "name": project}, "version": version} for version in batch
                ]
            }
            try:
                response = await fetch(
                    self._settings.osv_url,
                    method=HTTPMethod.POST,
                    body=json.dumps(body, separators=(",", ":")),
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
            except Exception as error:
                raise RepositoryError("OSV request failed") from error
            if not 200 <= response.status < 300:
                raise RepositoryError(f"OSV returned HTTP {response.status}")
            raw = await response.text()
            if len(raw.encode("utf-8")) > self._settings.maximum_metadata_bytes:
                raise RepositoryError("OSV response exceeds the configured metadata limit")
            try:
                parsed = json.loads(raw)
                advisories.update(parse_osv_results(parsed, batch))
            except (json.JSONDecodeError, InvalidOsvResponseError) as error:
                raise RepositoryError("OSV returned an invalid response") from error
        return advisories

    async def _store_advisories(
        self,
        project: str,
        key: str,
        advisories: dict[str, list[str]],
        checked_at: datetime,
    ) -> None:
        """Replace obsolete project scans with the newest version-set result."""
        await self._env.WHEELGUARD_DB.batch(
            [
                self._env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO advisory_scans (project, versions_key, payload, checked_at)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(project, versions_key) DO UPDATE SET
                        payload = excluded.payload,
                        checked_at = excluded.checked_at
                    """
                ).bind(
                    project,
                    key,
                    json.dumps(advisories, separators=(",", ":"), sort_keys=True),
                    _timestamp(checked_at),
                ),
                self._env.WHEELGUARD_DB.prepare(
                    "DELETE FROM advisory_scans WHERE project = ?1 AND versions_key != ?2"
                ).bind(project, key),
            ]
        )

    async def refresh_active_advisories(self, *, limit: int = 25) -> int:
        """Refresh the least-recently-scanned projects used inside the active window."""
        await self._load_runtime_settings()
        if not self._settings.osv_enabled:
            return 0
        now = datetime.now(UTC)
        cutoff = now - self._settings.advisory_active_window
        raw = (
            await self._env.WHEELGUARD_DB.prepare(
                """
            SELECT targets.project
            FROM advisory_targets AS targets
            JOIN projects ON projects.normalized_name = targets.project
            WHERE targets.requested_at >= ?1
            ORDER BY COALESCE(
                (SELECT MAX(checked_at) FROM advisory_scans WHERE project = targets.project),
                ''
            ) ASC,
            targets.requested_at DESC
            LIMIT ?2
            """
            )
            .bind(_timestamp(cutoff), limit)
            .raw()
        )
        refreshed = 0
        for row in _python(raw):
            if not row:
                continue
            project = str(row[0])
            cached = await self._cached_project(project)
            if cached is None:
                continue
            _, status, _ = await self._evaluate_advisories(project, cached[0], now=now, force=True)
            if status == "REFRESH":
                refreshed += 1
        await (
            self._env.WHEELGUARD_DB.prepare("DELETE FROM advisory_targets WHERE requested_at < ?1")
            .bind(_timestamp(cutoff))
            .run()
        )
        return refreshed

    async def _register_and_rewrite(self, request: Any, payload: SimplePayload) -> SimplePayload:
        """Register safe artifacts in D1 and replace upstream URLs with cache URLs."""
        files = payload.get("files")
        if not isinstance(files, list):
            payload["files"] = []
            return payload
        target = urlsplit(request.url)
        origin = f"{target.scheme}://{target.netloc}"
        visible: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        for raw_file in files:
            if not isinstance(raw_file, dict):
                continue
            artifact = self._safe_artifact(raw_file)
            if artifact is None:
                continue
            digest, filename, source_url, size = artifact
            file = dict(raw_file)
            file["url"] = f"{origin}/files/sha256/{digest}/{quote(filename, safe='')}"
            visible.append(file)
            records.append(
                {
                    "sha256": digest,
                    "filename": filename,
                    "source_url": source_url,
                    "size": size,
                    "verification_sha256": digest,
                }
            )
            metadata_digest = _metadata_sha256(file.get("core-metadata"))
            if metadata_digest is None:
                file.pop("core-metadata", None)
            else:
                records.append(
                    {
                        "sha256": digest,
                        "filename": f"{filename}.metadata",
                        "source_url": _append_metadata(source_url),
                        "size": None,
                        "verification_sha256": metadata_digest,
                    }
                )
        for start in range(0, len(records), 500):
            await self._register_artifact_records(records[start : start + 500])
        payload["files"] = visible
        return payload

    async def _register_artifact_records(self, records: list[dict[str, Any]]) -> None:
        """Upsert an artifact batch with one JSON-backed D1 statement."""
        await (
            self._env.WHEELGUARD_DB.prepare(
                """
            INSERT INTO artifacts (sha256, filename, source_url, size, verification_sha256)
            SELECT
                json_extract(value, '$.sha256'),
                json_extract(value, '$.filename'),
                json_extract(value, '$.source_url'),
                json_extract(value, '$.size'),
                json_extract(value, '$.verification_sha256')
            FROM json_each(?1)
            WHERE 1
            ON CONFLICT(sha256, filename) DO UPDATE SET
                source_url = excluded.source_url,
                size = excluded.size,
                verification_sha256 = excluded.verification_sha256
            """
            )
            .bind(json.dumps(records, separators=(",", ":")))
            .run()
        )

    def _safe_artifact(self, file: dict[str, Any]) -> tuple[str, str, str, int | None] | None:
        """Validate the hash, name, source host, and declared size of an artifact."""
        hashes = file.get("hashes")
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        filename = file.get("filename")
        source_url = file.get("url")
        size = file.get("size")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest.casefold()) is None:
            return None
        if not isinstance(filename, str) or not filename or filename != filename.rsplit("/", 1)[-1]:
            return None
        if "\\" in filename or any(ord(character) < 32 for character in filename):
            return None
        if not isinstance(source_url, str) or not self._allowed_source(source_url):
            return None
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
            return None
        if isinstance(size, int) and size > self._settings.maximum_artifact_bytes:
            return None
        return digest.casefold(), filename, source_url, size

    def _allowed_source(self, url: str) -> bool:
        """Return whether an artifact URL uses HTTPS on an allowlisted host."""
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.hostname.casefold() in self._settings.allowed_artifact_hosts
        )

    async def _artifact(self, request: Any, path: str) -> Response:
        """Stream an artifact from R2, populating it from the trusted upstream on miss."""
        parts = path.removeprefix("/files/sha256/").split("/", 1)
        if len(parts) != 2:
            return _error("Artifact not found", 404)
        digest, encoded_filename = parts
        filename = unquote(encoded_filename)
        if _SHA256.fullmatch(digest) is None or not filename or "/" in filename or "\\" in filename:
            return _error("Artifact not found", 404)
        key = f"sha256/{digest}/{filename}"
        cache_status = "HIT"
        stored = await self._env.WHEELGUARD_ARTIFACTS.get(key)
        if stored is None:
            row = _python(
                await self._env.WHEELGUARD_DB.prepare(
                    """
                    SELECT source_url, size, verification_sha256
                    FROM artifacts
                    WHERE sha256 = ?1 AND filename = ?2
                    """
                )
                .bind(digest, filename)
                .first()
            )
            if not isinstance(row, dict):
                return _error("Artifact not found", 404)
            try:
                await self._populate_artifact(key, filename, row)
            except RepositoryError as error:
                _log("artifact.rejected", digest=digest, filename=filename, error=str(error))
                return _error(str(error), 502)
            cache_status = "MISS"
            stored = await self._env.WHEELGUARD_ARTIFACTS.get(key)
            if stored is None:
                return _error("Artifact cache write failed", 502)
        headers = {
            "Cache-Control": "public, max-age=31536000, immutable",
            "Content-Length": str(stored.size),
            "Content-Type": "application/octet-stream",
            "ETag": str(stored.httpEtag),
            "X-Content-Type-Options": "nosniff",
            "X-Wheelguard-Artifact-Cache": cache_status,
        }
        return _body_response(stored.body, request, headers)

    async def _populate_artifact(
        self,
        key: str,
        filename: str,
        row: dict[str, Any],
    ) -> None:
        """Fetch an R2 miss and commit it only after SHA-256 verification."""
        source_url = str(row.get("source_url", ""))
        verification_sha256 = row.get("verification_sha256")
        if not isinstance(verification_sha256, str) or _SHA256.fullmatch(verification_sha256) is None:
            raise RepositoryError("Artifact has no valid verification hash")
        if not self._allowed_source(source_url):
            raise RepositoryError("Artifact source is not allowlisted")
        declared_size = row.get("size")
        if declared_size is not None and not isinstance(declared_size, int):
            raise RepositoryError("Artifact has invalid cached size metadata")
        buffer_body = False
        if declared_size is None:
            buffer_body = True
            declared_size = await self._probe_artifact_size(source_url, self._settings.maximum_metadata_bytes)
        elif declared_size > self._settings.maximum_artifact_bytes:
            raise RepositoryError("Artifact exceeds configured size limit")
        try:
            response = await fetch(source_url, redirect="follow")
        except Exception as error:
            raise RepositoryError("Upstream artifact request failed") from error
        if not 200 <= response.status < 300:
            raise RepositoryError(f"Upstream artifact returned HTTP {response.status}")
        final_url = str(getattr(response, "url", source_url))
        if not self._allowed_source(final_url):
            raise RepositoryError("Artifact redirect target is not allowlisted")
        response_size = _content_length(response.headers.get("content-length"))
        known_size = response_size if response_size is not None else declared_size
        if known_size is None:
            raise RepositoryError("Artifact size is unknown")
        if known_size > self._settings.maximum_artifact_bytes:
            raise RepositoryError("Artifact exceeds the configured size limit")
        if (
            not buffer_body
            and declared_size is not None
            and response_size is not None
            and declared_size != response_size
        ):
            raise RepositoryError("Artifact size does not match project metadata")
        body: Any = response.body
        if buffer_body:
            body = await response.buffer()
            buffered_bytes = body.to_bytes()
            if len(buffered_bytes) > self._settings.maximum_metadata_bytes:
                raise RepositoryError("Artifact exceeds configured metadata size limit")
            if hashlib.sha256(buffered_bytes).hexdigest() != verification_sha256:
                raise RepositoryError("Artifact SHA-256 does not match project metadata")
        put_options: dict[str, Any] = {
            "httpMetadata": {"contentType": "application/octet-stream"},
            "customMetadata": {"filename": filename, "source": final_url},
        }
        if not buffer_body:
            put_options["sha256"] = verification_sha256
        try:
            await self._env.WHEELGUARD_ARTIFACTS.put(key, body, **put_options)
        except Exception as error:
            _log("artifact.cache.write.error", filename=filename, error=str(error))
            raise RepositoryError("Artifact cache write or checksum verification failed") from error

    async def _probe_artifact_size(self, source_url: str, maximum_size: int) -> int:
        """Read a missing artifact size with an upstream HEAD request."""
        try:
            response = await fetch(source_url, method=HTTPMethod.HEAD, redirect="follow")
        except Exception as error:
            raise RepositoryError("Upstream artifact size request failed") from error
        if not 200 <= response.status < 300:
            raise RepositoryError(f"Upstream artifact size request returned HTTP {response.status}")
        final_url = str(getattr(response, "url", source_url))
        if not self._allowed_source(final_url):
            raise RepositoryError("Artifact size redirect target is not allowlisted")
        size = _content_length(response.headers.get("content-length"))
        if size is None:
            raise RepositoryError("Artifact size unknown")
        if size > maximum_size:
            raise RepositoryError("Artifact exceeds configured size limit")
        return size


def _positive_int(value: object, label: str) -> int:
    """Parse a positive integer setting."""
    try:
        parsed = int(str(value).replace(",", "").replace("_", ""))
    except ValueError as error:
        raise RepositoryError(f"Invalid {label} setting") from error
    if parsed <= 0:
        raise RepositoryError(f"Invalid {label} setting")
    return parsed


def _integer_value(values: dict[str, int | bool], key: str, default: int) -> int:
    """Return an integer runtime override without treating booleans as integers."""
    value = values.get(key, default)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _boolean_value(values: dict[str, int | bool], key: str, default: bool) -> bool:
    """Return a boolean runtime override."""
    value = values.get(key, default)
    return value if isinstance(value, bool) else default


def _boolean(value: object) -> bool:
    """Parse a strict boolean Worker variable."""
    normalized = str(value).casefold()
    if normalized not in {"true", "false"}:
        raise RepositoryError("Boolean Worker variables must be true or false")
    return normalized == "true"


def _python(value: Any) -> Any:
    """Convert a JavaScript proxy to native Python when required by Pyodide."""
    converter = getattr(value, "to_py", None)
    return converter() if callable(converter) else value


def _datetime(value: str) -> datetime:
    """Parse an aware ISO 8601 timestamp as UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    """Render a UTC timestamp in an interoperable form."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _content_length(value: object) -> int | None:
    """Parse a non-negative Content-Length header."""
    if value is None:
        return None
    try:
        parsed = int(str(value))
    except ValueError as error:
        raise RepositoryError("Upstream returned an invalid Content-Length") from error
    if parsed < 0:
        raise RepositoryError("Upstream returned an invalid Content-Length")
    return parsed


def _metadata_sha256(value: object) -> str | None:
    """Return a valid PEP 658 metadata checksum when one is advertised."""
    if not isinstance(value, dict):
        return None
    digest = value.get("sha256")
    if not isinstance(digest, str):
        return None
    normalized = digest.casefold()
    return normalized if _SHA256.fullmatch(normalized) is not None else None


def _advisory_mapping(value: object) -> dict[str, list[str]] | None:
    """Validate a cached version-to-advisory mapping."""
    if not isinstance(value, dict):
        return None
    result: dict[str, list[str]] = {}
    for version, identifiers in value.items():
        if not isinstance(version, str) or not isinstance(identifiers, list):
            return None
        if not all(isinstance(identifier, str) for identifier in identifiers):
            return None
        result[version] = identifiers
    return result


def _append_metadata(url: str) -> str:
    """Construct the PEP 658 sidecar URL without disturbing query parameters."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"{parts.path}.metadata", parts.query, ""))


def _simple_headers(media_type: str, cache_status: str) -> dict[str, str]:
    """Build common Simple API response headers."""
    return {
        "Cache-Control": "private, no-cache",
        "Content-Type": f"{media_type}; charset=utf-8",
        "Vary": "Accept, Authorization",
        "X-Content-Type-Options": "nosniff",
        "X-Wheelguard-Cache": cache_status,
        "X-Wheelguard-Policy": "minimum-age, overrides",
    }


def _json_response(payload: Any, request: Any, headers: dict[str, str]) -> Response:
    """Build a JSON response, omitting the body for HEAD."""
    if request.method == "HEAD":
        return Response(status=200, headers=headers)
    return Response.from_json(payload, headers=headers)


def _body_response(body: Any, request: Any, headers: dict[str, str]) -> Response:
    """Build a response, omitting the body for HEAD."""
    if request.method == "HEAD":
        return Response(headers=headers)
    return Response(body, headers=headers)


def _redirect(location: str) -> Response:
    """Build a permanent canonical-path redirect."""
    return Response(status=308, headers={"Location": location, "Cache-Control": "public, max-age=3600"})


def _with_trailing_slash(url: str) -> str:
    """Add a slash to a URL path while preserving its query string."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, f"{parts.path}/", parts.query, ""))


def _error(message: str, status: int, extra_headers: dict[str, str] | None = None) -> Response:
    """Build a non-cacheable JSON error response."""
    headers = {"Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8"}
    if extra_headers:
        headers.update(extra_headers)
    return Response.from_json({"detail": message}, status=status, headers=headers)


def _log(event: str, **fields: object) -> None:
    """Emit one compact structured Worker log record."""
    print(json.dumps({"event": event, **fields}, separators=(",", ":"), sort_keys=True))  # noqa: T201
