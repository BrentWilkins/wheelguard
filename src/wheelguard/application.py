"""Create and configure the Wheelguard HTTP application."""

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from inspect import isawaitable
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from packaging.utils import canonicalize_name
from starlette.middleware.base import RequestResponseEndpoint

from wheelguard.advisories import NoopAdvisoryPolicy, OsvAdvisoryPolicy
from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.auth import TokenAuthenticator
from wheelguard.cache import CachingRepository
from wheelguard.config import Settings
from wheelguard.database import Database
from wheelguard.models import (
    AdvisoryPolicy,
    ArtifactDownloadError,
    ArtifactNotFoundError,
    ArtifactPolicyDeniedError,
    ProjectRepository,
    SimplePayload,
    UpstreamNotFoundError,
    UpstreamRepositoryError,
)
from wheelguard.policy import ReleasePolicy, filename_version
from wheelguard.refresh import AdvisoryRefresher
from wheelguard.simple_api import (
    SIMPLE_HTML,
    SIMPLE_JSON,
    negotiate_content_type,
    render_project_html,
    render_root_html,
)
from wheelguard.upstream import PyPIRepository
from wheelguard.vulnerabilities import automatic_fixed_version_allows

Clock = Callable[[], datetime]
LOGGER = logging.getLogger(__name__)


def create_app(
    *,
    settings: Settings | None = None,
    repository: ProjectRepository | None = None,
    database: Database | None = None,
    artifact_service: ArtifactService | None = None,
    advisory_policy: AdvisoryPolicy | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    """Create a Wheelguard application with injectable infrastructure."""
    configured = settings or Settings.from_environment()
    state = database or Database(configured.data_dir / "wheelguard.db")
    upstream = repository or PyPIRepository(
        configured.upstream_url, timeout_seconds=configured.upstream_timeout_seconds
    )
    projects = CachingRepository(
        upstream,
        state,
        ttl=configured.metadata_ttl,
    )
    artifacts = artifact_service or ArtifactService(
        state,
        FileArtifactStore(configured.data_dir / "artifacts"),
        maximum_bytes=configured.maximum_artifact_bytes,
        allowed_hosts=configured.allowed_artifact_hosts,
        enforce_advisories=configured.osv_enabled,
        advisory_ttl=configured.advisory_ttl,
    )
    policy = ReleasePolicy(
        configured.minimum_age,
        allow_missing_upload_time=configured.allow_missing_upload_time,
    )
    advisories = advisory_policy or (
        OsvAdvisoryPolicy(
            state,
            url=configured.osv_url,
            ttl=configured.advisory_ttl,
            timeout_seconds=configured.upstream_timeout_seconds,
        )
        if configured.osv_enabled
        else NoopAdvisoryPolicy()
    )
    now = clock or (lambda: datetime.now(UTC))
    refresher = AdvisoryRefresher(
        state,
        advisories,
        active_window=configured.advisory_active_window,
        batch_size=configured.advisory_refresh_batch_size,
        clock=now,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await state.initialize()
        refresh_task = (
            asyncio.create_task(
                refresher.run(configured.advisory_refresh_interval),
                name="wheelguard-advisory-refresh",
            )
            if configured.osv_enabled
            else None
        )
        try:
            yield
        finally:
            if refresh_task is not None:
                refresh_task.cancel()
                with suppress(asyncio.CancelledError):
                    await refresh_task
            for resource in (projects, artifacts, advisories):
                close = getattr(resource, "aclose", None) or getattr(resource, "close", None)
                if close is None:
                    continue
                result = close()
                if isawaitable(result):
                    await result

    application = FastAPI(title="Wheelguard", version="0.2.0", lifespan=lifespan)
    authenticator = TokenAuthenticator(
        (*((configured.auth_token,) if configured.auth_token is not None else ()), *configured.auth_tokens)
    )

    @application.middleware("http")
    async def authenticate_repository(request: Request, call_next: RequestResponseEndpoint) -> Response:
        protected = request.url.path.startswith(("/simple", "/files/"))
        if protected and not authenticator.authorize(request.headers.get("Authorization")):
            return JSONResponse(
                {"detail": "Repository authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Wheelguard"'},
            )
        return await call_next(request)

    @application.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/simple/")
    async def simple_root(request: Request) -> Response:
        content_type = negotiate_content_type(request.headers.get("Accept"))
        if content_type is None:
            return JSONResponse(
                {"detail": "No supported Simple API representation was requested"},
                status_code=406,
            )
        names = await state.list_projects()
        headers = {"Vary": "Accept, Authorization", "X-Content-Type-Options": "nosniff"}
        if content_type == SIMPLE_JSON:
            return JSONResponse(
                {
                    "meta": {"api-version": "1.4"},
                    "projects": [{"name": name} for name in names],
                },
                media_type=SIMPLE_JSON,
                headers=headers,
            )
        return HTMLResponse(render_root_html(names), media_type=SIMPLE_HTML, headers=headers)

    @application.get("/simple/{project}/", name="simple_project")
    async def simple_project(project: str, request: Request) -> Response:
        normalized = canonicalize_name(project)
        if project != normalized:
            return RedirectResponse(request.url_for("simple_project", project=normalized), status_code=308)
        content_type = negotiate_content_type(request.headers.get("Accept"))
        if content_type is None:
            return JSONResponse(
                {"detail": "No supported Simple API representation was requested"},
                status_code=406,
            )
        try:
            upstream = await projects.get_project(normalized)
        except UpstreamNotFoundError:
            return JSONResponse({"detail": "Project not found"}, status_code=404)
        except UpstreamRepositoryError as error:
            return JSONResponse({"detail": str(error)}, status_code=502)

        requested_at = now()
        if configured.osv_enabled:
            await state.record_advisory_target(normalized, requested_at=requested_at)
        evaluated = await advisories.apply(normalized, upstream.payload)
        automatic_allows = automatic_fixed_version_allows(
            evaluated.payload,
            _advisories_in(evaluated.payload),
            now=requested_at,
            minimum_age=configured.minimum_age,
            fallback_minimum_age=configured.fallback_minimum_age,
        )
        if automatic_allows:
            LOGGER.warning(
                "policy.vulnerability_fallback project=%s versions=%s",
                normalized,
                sorted(automatic_allows),
            )
        filtered = policy.apply(evaluated.payload, now=requested_at, overrides=automatic_allows)
        published = await artifacts.rewrite_urls(
            normalized,
            filtered.payload,
            url_for=lambda digest, filename: str(request.url_for("artifact", digest=digest, filename=filename)),
        )
        headers = {
            "Vary": "Accept, Authorization",
            "X-Content-Type-Options": "nosniff",
            "X-Wheelguard-Hidden-Files": str(filtered.hidden_files),
            "X-Wheelguard-Cache": upstream.cache_status,
            "X-Wheelguard-Advisories": (f"{evaluated.status}; vulnerable-files={evaluated.vulnerable_files}"),
            "X-Wheelguard-Policy": "minimum-age, vulnerability-fallback" if automatic_allows else "minimum-age",
        }
        if upstream.last_serial is not None:
            headers["X-PyPI-Last-Serial"] = upstream.last_serial
        if content_type == SIMPLE_JSON:
            return JSONResponse(published, media_type=SIMPLE_JSON, headers=headers)
        return HTMLResponse(render_project_html(published), media_type=SIMPLE_HTML, headers=headers)

    @application.get("/files/sha256/{digest}/{filename}", name="artifact")
    async def artifact(digest: str, filename: str) -> Response:
        try:
            path = await artifacts.get_path(digest, filename)
        except ArtifactPolicyDeniedError as error:
            return JSONResponse(
                {"detail": str(error)},
                status_code=403,
                headers={
                    "Cache-Control": "private, no-store",
                    "X-Wheelguard-Policy": "artifact-denied",
                },
            )
        except ArtifactNotFoundError:
            return JSONResponse({"detail": "Artifact not found"}, status_code=404)
        except ArtifactDownloadError as error:
            return JSONResponse({"detail": str(error)}, status_code=502)
        return StreamingResponse(
            _read_file(path),
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "private, max-age=31536000, immutable",
                "ETag": f'"sha256:{digest.casefold()}"',
                "Content-Length": str(path.stat().st_size),
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
                "Vary": "Authorization",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return application


app = create_app()


async def _read_file(path: Path) -> AsyncIterator[bytes]:
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            yield chunk


def _advisories_in(payload: SimplePayload) -> dict[str, list[str]]:
    """Recover Wheelguard advisory markers from an evaluated Simple API payload."""
    advisories: dict[str, list[str]] = {}
    files = payload.get("files", [])
    if not isinstance(files, list):
        return advisories
    for file in files:
        if not isinstance(file, dict):
            continue
        version = filename_version(file.get("filename"))
        identifiers = file.get("wheelguard-advisories")
        if version is not None and isinstance(identifiers, list):
            advisories[str(version)] = [identifier for identifier in identifiers if isinstance(identifier, str)]
    return advisories
