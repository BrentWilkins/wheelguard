"""Create and configure the Wheelguard HTTP application."""

import asyncio
import html
import logging
import secrets
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from inspect import isawaitable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from packaging.utils import canonicalize_name
from starlette.middleware.base import RequestResponseEndpoint

from wheelguard.admin import InvalidOverrideError, admin_content_security_policy
from wheelguard.admin_service import AdminService
from wheelguard.advisories import NoopAdvisoryPolicy, OsvAdvisoryPolicy
from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.auth import AdminSessionAuthenticator, TokenAuthenticator, authorization_token
from wheelguard.cache import CachingRepository
from wheelguard.config import Settings
from wheelguard.database import Database
from wheelguard.identity import IdentityError, entra_actor
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
from wheelguard.runtime_settings import InvalidSettingsError
from wheelguard.simple_api import (
    SIMPLE_JSON,
    html_response_media_type,
    negotiate_content_type,
    render_project_html,
    render_root_html,
)
from wheelguard.upstream import PyPIRepository
from wheelguard.vulnerabilities import automatic_fixed_version_allows

Clock = Callable[[], datetime]
LOGGER = logging.getLogger(__name__)
ADMIN_SESSION_COOKIE = "wheelguard_admin_session"


def create_app(
    *,
    settings: Settings | None = None,
    repository: ProjectRepository | None = None,
    database: Any | None = None,
    artifact_service: Any | None = None,
    advisory_policy: AdvisoryPolicy | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    """Create a Wheelguard application with injectable infrastructure."""
    configured = settings or Settings.from_environment()
    azure_credential: Any | None = None
    blob_service: Any | None = None
    blob_bucket: Any | None = None
    postgres_database = configured.database_url is not None
    if database is not None:
        state = database
    elif configured.database_url is not None:
        from azure.identity.aio import DefaultAzureCredential

        from wheelguard.postgres import PostgresDatabase

        azure_credential = DefaultAzureCredential()
        state = PostgresDatabase(configured.database_url, azure_credential, configured.database_token_scope)
    else:
        state = Database(configured.data_dir / "wheelguard.db")
    upstream = repository or PyPIRepository(
        configured.upstream_url, timeout_seconds=configured.upstream_timeout_seconds
    )
    projects = CachingRepository(
        upstream,
        state,
        ttl=configured.metadata_ttl,
    )
    if artifact_service is not None:
        artifacts = artifact_service
    elif configured.azure_storage_account_url is not None:
        from azure.identity.aio import DefaultAzureCredential

        from wheelguard.azure_artifacts import AzureArtifactService
        from wheelguard.azure_storage import AzureBlobBucket

        azure_credential = azure_credential or DefaultAzureCredential()
        blob_bucket, blob_service = AzureBlobBucket.from_account_url(
            configured.azure_storage_account_url, configured.azure_artifact_container, azure_credential
        )
        artifacts = AzureArtifactService(
            state,
            blob_bucket,
            maximum_bytes=configured.maximum_artifact_bytes,
            allowed_hosts=configured.allowed_artifact_hosts,
            enforce_advisories=configured.osv_enabled,
            advisory_ttl=configured.advisory_ttl,
        )
    else:
        artifacts = ArtifactService(
            state,
            FileArtifactStore(configured.data_dir / "artifacts"),
            maximum_bytes=configured.maximum_artifact_bytes,
            allowed_hosts=configured.allowed_artifact_hosts,
            enforce_advisories=configured.osv_enabled,
            advisory_ttl=configured.advisory_ttl,
        )
    if (
        blob_bucket is not None
        and configured.publisher_oidc_issuer is not None
        and configured.publisher_oidc_projects
        and postgres_database
    ):
        from wheelguard.identity import GitLabOidcValidator
        from wheelguard.private_service import PrivatePackageService

        private_packages: Any | None = PrivatePackageService(
            state,
            blob_bucket,
            GitLabOidcValidator(
                configured.publisher_oidc_issuer,
                configured.publisher_oidc_audience,
                configured.publisher_oidc_projects,
            ),
            upstream_url=configured.upstream_url,
            maximum_bytes=configured.maximum_artifact_bytes,
        )
    else:
        private_packages = None
    admin = (
        AdminService(
            state,
            {
                "minimum_age_days": configured.minimum_age.days,
                "fallback_minimum_age_hours": int(configured.fallback_minimum_age.total_seconds() // 3600),
                "allow_missing_upload_time": configured.allow_missing_upload_time,
                "metadata_ttl_seconds": int(configured.metadata_ttl.total_seconds()),
                "maximum_artifact_bytes": configured.maximum_artifact_bytes,
                "osv_enabled": configured.osv_enabled,
                "advisory_ttl_seconds": int(configured.advisory_ttl.total_seconds()),
                "advisory_active_days": configured.advisory_active_window.days,
            },
        )
        if (configured.entra_admin_enabled or configured.admin_token is not None) and postgres_database
        else None
    )
    advisories = advisory_policy or (
        OsvAdvisoryPolicy(
            state,
            url=configured.osv_url,
            ttl=configured.advisory_ttl,
            timeout_seconds=configured.upstream_timeout_seconds,
        )
        if configured.osv_enabled or postgres_database
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
            if configured.osv_enabled and not postgres_database
            else None
        )
        try:
            yield
        finally:
            if refresh_task is not None:
                refresh_task.cancel()
                with suppress(asyncio.CancelledError):
                    await refresh_task
            for resource in (projects, artifacts, advisories, private_packages):
                if resource is None:
                    continue
                close = getattr(resource, "aclose", None) or getattr(resource, "close", None)
                if close is None:
                    continue
                result = close()
                if isawaitable(result):
                    await result
            if blob_service is not None:
                await blob_service.close()
            if azure_credential is not None:
                await azure_credential.close()

    application = FastAPI(title="Wheelguard", version="0.2.1", lifespan=lifespan)
    authenticator = TokenAuthenticator(
        (*((configured.auth_token,) if configured.auth_token is not None else ()), *configured.auth_tokens)
    )
    admin_authenticator = TokenAuthenticator(configured.admin_token)
    admin_sessions = AdminSessionAuthenticator(configured.admin_token)

    @application.middleware("http")
    async def authenticate_repository(request: Request, call_next: RequestResponseEndpoint) -> Response:
        protected = request.url.path.startswith(("/simple", "/files/"))
        if protected:
            authorization = request.headers.get("Authorization")
            managed_authenticate = (
                getattr(state, "authenticate_repository_token", None) if configured.managed_token_auth_enabled else None
            )
            authenticated = not authenticator.enabled and managed_authenticate is None
            if authenticator.enabled and authenticator.authorize(authorization):
                authenticated = True
            candidate = authorization_token(authorization)
            if not authenticated and managed_authenticate is not None and candidate is not None:
                authenticated = await managed_authenticate(candidate)
            if not authenticated:
                return JSONResponse(
                    {"detail": "Repository authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="Wheelguard"'},
                )
        return await call_next(request)

    @application.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/")
    async def landing_page(request: Request) -> Response:
        packages = await private_packages.catalog() if private_packages is not None else []
        public_origin = configured.public_url or str(request.base_url).rstrip("/")
        return HTMLResponse(
            _render_landing_page(
                packages,
                public_origin=public_origin,
                documentation_url=configured.documentation_url,
            ),
            headers={
                "Cache-Control": "private, max-age=60",
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @application.get("/packages/{project}/", include_in_schema=False)
    async def package_page(project: str, request: Request) -> Response:
        normalized = canonicalize_name(project)
        if project != normalized:
            return RedirectResponse(f"/packages/{normalized}/", status_code=308)
        details = await private_packages.details(normalized) if private_packages is not None else None
        if details is None:
            return HTMLResponse(
                _render_package_page(None, normalized),
                status_code=404,
                headers=_catalog_page_headers(),
            )
        return HTMLResponse(_render_package_page(details, normalized), headers=_catalog_page_headers())

    @application.get("/readyz")
    async def readiness() -> Response:
        try:
            await state.health()
        except Exception:
            LOGGER.exception("Readiness database check failed")
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

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
        return HTMLResponse(
            render_root_html(names),
            media_type=html_response_media_type(request.headers.get("Accept")),
            headers=headers,
        )

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
        public_origin = configured.public_url or str(request.base_url).rstrip("/")
        if private_packages is not None and await private_packages.owns(normalized):
            payload = await private_packages.listing(normalized, public_origin)
            headers = {
                "Cache-Control": "private, no-store",
                "Vary": "Accept, Authorization",
                "X-Wheelguard-Policy": "private, administrator-overrides",
                "X-Wheelguard-Advisories": "PRIVATE",
            }
            if content_type == SIMPLE_JSON:
                return JSONResponse(payload, media_type=SIMPLE_JSON, headers=headers)
            return HTMLResponse(
                render_project_html(payload),
                media_type=html_response_media_type(request.headers.get("Accept")),
                headers=headers,
            )
        runtime = await state.settings() if postgres_database else {}
        metadata_ttl = timedelta(
            seconds=int(runtime.get("metadata_ttl_seconds", configured.metadata_ttl.total_seconds()))
        )
        minimum_age = timedelta(days=int(runtime.get("minimum_age_days", configured.minimum_age.days)))
        fallback_minimum_age = timedelta(
            hours=int(
                runtime.get("fallback_minimum_age_hours", configured.fallback_minimum_age.total_seconds() // 3600)
            )
        )
        advisory_ttl = timedelta(
            seconds=int(runtime.get("advisory_ttl_seconds", configured.advisory_ttl.total_seconds()))
        )
        osv_enabled = bool(runtime.get("osv_enabled", configured.osv_enabled)) or advisory_policy is not None
        request_policy = ReleasePolicy(
            minimum_age,
            allow_missing_upload_time=bool(
                runtime.get("allow_missing_upload_time", configured.allow_missing_upload_time)
            ),
        )
        configure_artifacts = getattr(artifacts, "configure_policy", None)
        if configure_artifacts is not None:
            configure_artifacts(
                enforce_advisories=osv_enabled,
                advisory_ttl=advisory_ttl,
                maximum_bytes=int(runtime.get("maximum_artifact_bytes", configured.maximum_artifact_bytes)),
            )
        try:
            upstream = await projects.get_project(normalized, ttl=metadata_ttl)
        except UpstreamNotFoundError:
            return JSONResponse({"detail": "Project not found"}, status_code=404)
        except UpstreamRepositoryError as error:
            return JSONResponse({"detail": str(error)}, status_code=502)

        requested_at = now()
        if osv_enabled:
            await state.record_advisory_target(normalized, requested_at=requested_at)
        if osv_enabled and isinstance(advisories, OsvAdvisoryPolicy):
            evaluated = await advisories.apply(normalized, upstream.payload, ttl=advisory_ttl)
        elif osv_enabled:
            evaluated = await advisories.apply(normalized, upstream.payload)
        else:
            evaluated = await NoopAdvisoryPolicy().apply(normalized, upstream.payload)
        automatic_allows = automatic_fixed_version_allows(
            evaluated.payload,
            _advisories_in(evaluated.payload),
            now=requested_at,
            minimum_age=minimum_age,
            fallback_minimum_age=fallback_minimum_age,
        )
        if automatic_allows:
            LOGGER.warning(
                "policy.vulnerability_fallback project=%s versions=%s",
                normalized,
                sorted(automatic_allows),
            )
        combined_overrides = dict(automatic_allows)
        if postgres_database:
            combined_overrides.update(await state.active_overrides(normalized, requested_at))
        filtered = request_policy.apply(
            evaluated.payload,
            now=requested_at,
            overrides=combined_overrides,
            fallback_minimum_age=fallback_minimum_age,
        )
        published = await artifacts.rewrite_urls(
            normalized,
            filtered.payload,
            url_for=lambda digest, filename: f"{public_origin}/files/sha256/{digest}/{quote(filename, safe='')}",
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
        return HTMLResponse(
            render_project_html(published),
            media_type=html_response_media_type(request.headers.get("Accept")),
            headers=headers,
        )

    @application.get("/files/sha256/{digest}/{filename}", name="artifact")
    async def artifact(digest: str, filename: str) -> Response:
        try:
            get_stream = getattr(artifacts, "get_stream", None)
            if get_stream is not None:
                stored = await get_stream(digest, filename)
                return StreamingResponse(
                    stored.iter_bytes(),
                    media_type="application/octet-stream",
                    headers={
                        "Cache-Control": "private, max-age=31536000, immutable",
                        "ETag": f'"sha256:{digest.casefold()}"',
                        "Content-Length": str(stored.size),
                        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
                        "Vary": "Authorization",
                        "X-Content-Type-Options": "nosniff",
                    },
                )
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

    @application.post("/upload/")
    async def upload_private(request: Request) -> Response:
        from wheelguard.upload_form import UploadError

        if private_packages is None:
            return JSONResponse({"detail": "Private publishing is disabled"}, status_code=503)
        try:
            identity = await private_packages.authenticate(request)
            if postgres_database:
                runtime = await state.settings()
                private_packages.configure_maximum_bytes(
                    int(runtime.get("maximum_artifact_bytes", configured.maximum_artifact_bytes))
                )
            result = await private_packages.upload(request, identity)
        except IdentityError as error:
            return JSONResponse(
                {"detail": str(error)},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="wheelguard-upload"'},
            )
        except UploadError as error:
            return JSONResponse({"detail": str(error)}, status_code=error.status)
        except Exception:
            LOGGER.exception("Private package publication failed")
            return JSONResponse(
                {"detail": "Private publication could not be completed; retry the same file"}, status_code=503
            )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @application.get("/files/private/sha256/{digest}/{filename}")
    async def private_artifact(digest: str, filename: str) -> Response:
        if private_packages is None:
            return JSONResponse({"detail": "Artifact not found"}, status_code=404)
        try:
            result = await private_packages.artifact(digest, filename)
        except PermissionError as error:
            return JSONResponse({"detail": str(error)}, status_code=403)
        if result is None:
            return JSONResponse({"detail": "Artifact not found"}, status_code=404)
        stored, row = result
        return StreamingResponse(
            stored.iter_bytes(),
            media_type="application/octet-stream",
            headers={
                "Content-Length": str(row["size"]),
                "Cache-Control": "private, no-store",
                "Vary": "Authorization",
                "ETag": f'"sha256:{digest}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    def administrator(request: Request) -> tuple[str, AdminService]:
        if admin is None:
            raise IdentityError("Administration is disabled")
        if configured.entra_admin_enabled:
            try:
                return entra_actor(request.headers.get("x-ms-client-principal")), admin
            except IdentityError:
                if not admin_authenticator.enabled:
                    raise
        if admin_authenticator.enabled and admin_authenticator.authorize(request.headers.get("authorization")):
            return configured.admin_token_actor, admin
        if admin_sessions.authorize(request.cookies.get(ADMIN_SESSION_COOKIE), now()):
            return configured.admin_token_actor, admin
        raise IdentityError("Administrator authentication required")

    def admin_denied(error: IdentityError) -> JSONResponse:
        headers = (
            {"WWW-Authenticate": 'Basic realm="Wheelguard administration"'} if admin_authenticator.enabled else None
        )
        return JSONResponse({"detail": str(error)}, status_code=401 if headers else 403, headers=headers)

    def login_page(*, error: str | None = None, status_code: int = 200) -> HTMLResponse:
        message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
        body = _ADMIN_LOGIN_PAGE.replace("{{ actor }}", html.escape(configured.admin_token_actor, quote=True)).replace(
            "{{ error }}", message
        )
        return HTMLResponse(
            body,
            status_code=status_code,
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                    "base-uri 'none'; frame-ancestors 'none'"
                ),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @application.get("/admin/login")
    async def admin_login_page(request: Request) -> Response:
        if not admin_authenticator.enabled:
            return admin_denied(IdentityError("Administrator token sign-in is disabled"))
        try:
            administrator(request)
        except IdentityError:
            return login_page()
        return RedirectResponse("/admin/", status_code=303)

    @application.post("/admin/login")
    async def admin_login(request: Request) -> Response:
        if not admin_authenticator.enabled:
            return admin_denied(IdentityError("Administrator token sign-in is disabled"))
        if request.headers.get("origin") is not None or request.headers.get("sec-fetch-site") is not None:
            try:
                _same_origin(request, configured.public_url)
            except IdentityError as error:
                return login_page(error=str(error), status_code=403)
        form = await request.form()
        username, password = str(form.get("username", "")), str(form.get("password", ""))
        if username != configured.admin_token_actor or not admin_authenticator.authorize(f"Bearer {password}"):
            return login_page(error="Invalid username or password", status_code=401)
        response = RedirectResponse("/admin/", status_code=303)
        response.set_cookie(
            ADMIN_SESSION_COOKIE,
            admin_sessions.issue(now()),
            max_age=8 * 60 * 60,
            path="/admin",
            secure=(urlsplit(configured.public_url).scheme if configured.public_url else request.url.scheme) == "https",
            httponly=True,
            samesite="strict",
        )
        return response

    @application.post("/admin/logout")
    async def admin_logout(request: Request) -> Response:
        if request.headers.get("origin") is not None or request.headers.get("sec-fetch-site") is not None:
            try:
                _same_origin(request, configured.public_url)
            except IdentityError as error:
                return admin_denied(error)
        response = RedirectResponse("/admin/login", status_code=303)
        response.delete_cookie(ADMIN_SESSION_COOKIE, path="/admin")
        return response

    @application.get("/admin/")
    async def admin_page(request: Request) -> Response:
        try:
            actor, _ = administrator(request)
        except IdentityError as error:
            if admin_authenticator.enabled and request.headers.get("authorization") is None:
                return RedirectResponse("/admin/login", status_code=303)
            return admin_denied(error)
        nonce = secrets.token_urlsafe(24)
        logout = (
            '<form class="logout" method="post" action="/admin/logout"><button type="submit">Sign out</button></form>'
        )
        body = (
            _ADMIN_PAGE.replace("{{ actor }}", html.escape(actor))
            .replace("{{ nonce }}", nonce)
            .replace("{{ logout }}", logout if admin_authenticator.enabled else "")
        )
        return HTMLResponse(
            body,
            headers={
                "Cache-Control": "no-store",
                "Content-Security-Policy": admin_content_security_policy(nonce),
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @application.get("/admin/api/settings")
    async def admin_settings(request: Request) -> Response:
        try:
            _, service = administrator(request)
            return JSONResponse(await service.settings())
        except IdentityError as error:
            return admin_denied(error)

    @application.patch("/admin/api/settings")
    async def admin_update_settings(request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            return JSONResponse(await service.update_settings(await _json_body(request), actor))
        except IdentityError as error:
            return admin_denied(error)
        except (InvalidSettingsError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

    @application.delete("/admin/api/settings/{key}")
    async def admin_reset_setting(key: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            return JSONResponse(await service.reset_setting(key, actor))
        except IdentityError as error:
            return admin_denied(error)
        except KeyError as error:
            return JSONResponse({"detail": str(error.args[0])}, status_code=404)

    @application.get("/admin/api/overrides")
    async def admin_overrides(request: Request) -> Response:
        try:
            _, service = administrator(request)
            return JSONResponse(await service.overrides())
        except IdentityError as error:
            return admin_denied(error)

    @application.post("/admin/api/overrides")
    async def admin_create_override(request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            return JSONResponse(await service.create_override(await _json_body(request), actor), status_code=201)
        except IdentityError as error:
            return admin_denied(error)
        except (InvalidOverrideError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

    @application.patch("/admin/api/overrides/{identifier}")
    async def admin_replace_override(identifier: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            return JSONResponse(await service.create_override(await _json_body(request), actor, replaces=identifier))
        except IdentityError as error:
            return admin_denied(error)
        except KeyError as error:
            return JSONResponse({"detail": str(error.args[0])}, status_code=404)
        except (InvalidOverrideError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

    @application.delete("/admin/api/overrides/{identifier}")
    async def admin_revoke_override(identifier: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            await service.revoke_override(identifier, actor)
            return Response(status_code=204)
        except IdentityError as error:
            return admin_denied(error)
        except (KeyError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=404)

    @application.get("/admin/api/private-projects")
    async def admin_private_projects(request: Request) -> Response:
        try:
            _, service = administrator(request)
            return JSONResponse(await service.private_projects())
        except IdentityError as error:
            return admin_denied(error)

    @application.post("/admin/api/private-projects/{name}/approve")
    async def admin_approve_private(name: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request, configured.public_url)
            return JSONResponse(await service.approve_private_project(name, actor))
        except IdentityError as error:
            return admin_denied(error)
        except KeyError as error:
            return JSONResponse({"detail": str(error.args[0])}, status_code=404)
        except ValueError as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

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


async def _json_body(request: Request, maximum_bytes: int = 16_384) -> object:
    body = await request.body()
    if len(body) > maximum_bytes:
        raise ValueError("Request body is too large")
    try:
        import json

        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Request body must be valid JSON") from error


def _same_origin(request: Request, public_origin: str | None = None) -> None:
    origin = request.headers.get("origin")
    fetch_site = (request.headers.get("sec-fetch-site") or "").casefold()
    expected = public_origin or f"{request.url.scheme}://{request.url.netloc}"
    if origin == expected or (origin is None and fetch_site == "same-origin"):
        return
    raise IdentityError("Cross-origin administrator writes are not allowed")


_LANDING_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wheelguard · Private Python packages</title><style>
:root{color-scheme:light dark}body{font:16px/1.6 system-ui;max-width:62rem;margin:8vh auto;padding:0 1.25rem}
h1{font-size:clamp(2.2rem,6vw,4rem);line-height:1.05;margin-bottom:.4rem}.tagline{font-size:1.25rem;max-width:44rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:1rem;margin:2rem 0}
.card{border:1px solid GrayText;border-radius:.6rem;padding:1rem}.card h2{margin-top:0;font-size:1.1rem}
.packages{list-style:none;padding:0;margin:.5rem 0}.packages li{display:flex;justify-content:space-between;gap:1rem;
padding:.45rem 0;border-bottom:1px solid color-mix(in srgb,GrayText 35%,transparent)}
a{color:LinkText}code{font-size:.95em}.status{display:inline-block;border:1px solid #187b36;border-radius:2rem;padding:.15rem .65rem}
</style></head><body>
<p class="status">Private package service</p><h1>Wheelguard</h1>
<p class="tagline">A policy-aware, outage-resistant path to trusted Python packages.</p>
<div class="grid"><section class="card"><h2>Get started</h2><p>Configure <code>uv</code> or <code>pip</code>,
publish private packages, and use the controlled outage procedure.</p>{{ documentation_link }}</section>
<section class="card"><h2>Administration</h2><p>Manage release policy, overrides, and private-name collisions.</p>
<a href="/admin/">Sign in to administration →</a></section>
<section class="card"><h2>Package index</h2><p>Use this URL in <code>uv</code>, <code>pip</code>, and CI:</p>
<p><code>{{ index_url }}</code></p>
</section></div><section class="card"><h2>Private packages</h2>{{ private_packages }}</section>
<p>Package bytes and PEP 658 metadata are verified by SHA-256 before entering the private cache.</p>
</body></html>"""


def _render_landing_page(
    packages: list[tuple[str, str]], *, public_origin: str = "", documentation_url: str | None = None
) -> str:
    """Render the human landing page with a safe private package catalog."""
    if packages:
        items = "".join(
            f'<li><a href="/packages/{quote(name, safe="")}/">{html.escape(name)}</a>'
            f"<span>{html.escape(version)}</span></li>"
            for name, version in packages
        )
        catalog = f'<ul class="packages">{items}</ul>'
    else:
        catalog = "<p>No private packages have been published yet.</p>"
    documentation_link = (
        f'<a href="{html.escape(documentation_url, quote=True)}" rel="noreferrer">Open the user guide →</a>'
        if documentation_url
        else ""
    )
    index_url = f"{public_origin.rstrip('/')}/simple/" if public_origin else "/simple/"
    return (
        _LANDING_PAGE.replace("{{ private_packages }}", catalog)
        .replace("{{ documentation_link }}", documentation_link)
        .replace("{{ index_url }}", html.escape(index_url))
    )


def _catalog_page_headers() -> dict[str, str]:
    return {
        "Cache-Control": "private, max-age=60",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }


def _render_package_page(details: dict[str, str | None] | None, name: str) -> str:
    """Render package context while links fail gracefully behind GitLab auth."""
    escaped_name = html.escape(name)
    if details is None:
        body = f"<h1>{escaped_name}</h1><p>This internal package is not available.</p>"
        title = f"{escaped_name} · Wheelguard"
    else:
        version = html.escape(str(details["version"]))
        repository_url = details.get("repository_url")
        changelog_url = details.get("changelog_url")
        repository = (
            f'<a href="{html.escape(repository_url, quote=True)}" rel="noreferrer">Open repository →</a>'
            if repository_url
            else "Repository link not published."
        )
        changelog = (
            f'<a href="{html.escape(changelog_url, quote=True)}" rel="noreferrer">Open changelog →</a>'
            if changelog_url
            else "No changelog link has been published yet."
        )
        body = (
            f'<p><a href="/">← All packages</a></p><h1>{escaped_name}</h1>'
            f'<p class="version">Latest version: <strong>{version}</strong></p>'
            f"<section><h2>Changelog</h2><p>{changelog}</p>"
            '<p class="note">This link may require additional repository access. '
            "If access is denied, contact the package owner.</p></section>"
            f"<section><h2>Source</h2><p>{repository}</p></section>"
        )
        title = f"{escaped_name} {version} · Wheelguard"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{color-scheme:light dark}}body{{font:16px/1.6 system-ui;max-width:52rem;margin:8vh auto;padding:0 1.25rem}}
h1{{font-size:clamp(2rem,6vw,3.5rem);line-height:1.1}}section{{border-top:1px solid GrayText;margin-top:2rem;padding-top:1rem}}
a{{color:LinkText}}.version{{font-size:1.2rem}}.note{{color:GrayText;max-width:42rem}}
</style></head><body>{body}</body></html>"""


_ADMIN_LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Wheelguard administration</title><style>
:root{color-scheme:light dark}body{font:16px/1.5 system-ui;max-width:28rem;margin:10vh auto;padding:0 1rem}
form{display:grid;gap:1rem;padding:1.5rem;border:1px solid GrayText;border-radius:.5rem}
label{display:grid;gap:.3rem}input,button{font:inherit;padding:.65rem}.error{color:#d33}
</style></head><body><h1>Wheelguard administration</h1>
<p>Sign in with the temporary administrator credential.</p>{{ error }}
<form method="post" action="/admin/login">
<label>Username<input name="username" value="{{ actor }}" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required autofocus></label>
<button type="submit">Sign in</button></form></body></html>"""


_ADMIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wheelguard administration</title><style>
:root{color-scheme:light dark}body{font:16px/1.5 system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem}
form,.settings{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:1rem}
label{display:grid;gap:.3rem}input,select,button{font:inherit;padding:.55rem}.wide{grid-column:1/-1}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid GrayText;padding:.6rem;text-align:left}
.scroll{overflow:auto}.error{color:#d33}.success{color:#187b36}.setting{border:1px solid GrayText;padding:.7rem}
.logout{display:block;float:right}
</style></head><body>
{{ logout }}<h1>Wheelguard administration</h1><p>Signed in as <strong>{{ actor }}</strong>.</p>
<h2 id="private-packages">Private package collisions</h2><div id="private"></div>
<h2>Runtime policy settings</h2><div class="settings" id="settings"></div>
<p><button id="save-settings">Save settings</button> <span id="settings-status"></span></p>
<h2>Release overrides</h2>
<form id="override-form"><label>Project<input name="project" required></label>
<label>Version<input name="version" required></label><label>Action<select name="action">
<option value="block">Block</option><option value="allow">Allow</option></select></label>
<label>Expires at<input name="expires_at" type="datetime-local"></label>
<label class="wide">Reason<input name="reason" maxlength="500" required></label>
<button type="submit">Create override</button><span id="override-status"></span></form>
<div class="scroll"><table><thead><tr><th>Project</th><th>Version</th><th>Action</th><th>Reason</th>
<th>Created</th><th>Status</th><th></th></tr></thead><tbody id="overrides"></tbody></table></div>
<script nonce="{{ nonce }}">
const api=async(url,options)=>{const response=await fetch(url,options);const body=response.status===204?null:
  await response.json().catch(()=>null);if(!response.ok)throw new Error(body?.detail||`HTTP ${response.status}`);return body};
const text=(element,message,kind='')=>{element.textContent=message;element.className=kind};
async function loadSettings(){const body=await api('/admin/api/settings');const root=document.querySelector('#settings');
  root.replaceChildren();for(const setting of body.settings){const box=document.createElement('label');box.className='setting';
    box.textContent=setting.label;let input;if(setting.kind==='boolean'){input=document.createElement('select');
      for(const value of ['true','false']){const option=new Option(value,value,value===String(setting.value));input.add(option)}}
    else{input=document.createElement('input');input.type='number';input.min=setting.minimum;input.max=setting.maximum;
      input.value=setting.value}input.dataset.key=setting.key;input.dataset.initial=String(setting.value);box.append(input);
    const detail=document.createElement('small');detail.textContent=`${setting.description} Default: ${setting.default}`;
    box.append(detail);root.append(box)}}
document.querySelector('#save-settings').onclick=async()=>{const status=document.querySelector('#settings-status');const updates={};
  for(const input of document.querySelectorAll('#settings [data-key]'))if(input.value!==input.dataset.initial)
    updates[input.dataset.key]=input.value;if(!Object.keys(updates).length)return text(status,'No changes.');
  try{await api('/admin/api/settings',{method:'PATCH',headers:{'content-type':'application/json'},
    body:JSON.stringify(updates)});text(status,'Saved.','success');await loadSettings()}catch(error){text(status,error.message,'error')}};
async function loadOverrides(){const rows=await api('/admin/api/overrides');const root=document.querySelector('#overrides');
  root.replaceChildren();for(const row of rows){const tr=document.createElement('tr');const expired=row.expires_at&&
    new Date(row.expires_at)<=new Date();const state=row.revoked_at?'Revoked':expired?'Expired':'Active';
    for(const value of [row.project,row.version,row.action,row.reason,new Date(row.created_at).toLocaleString(),state]){
      const td=document.createElement('td');td.textContent=value;tr.append(td)}const action=document.createElement('td');
    if(state==='Active'){const button=document.createElement('button');button.textContent='Revoke';button.onclick=async()=>{
      await api(`/admin/api/overrides/${row.id}`,{method:'DELETE'});await loadOverrides()};action.append(button)}
    tr.append(action);root.append(tr)}}
document.querySelector('#override-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget;
  const status=document.querySelector('#override-status');const body=Object.fromEntries(new FormData(form));
  if(body.expires_at)body.expires_at=new Date(body.expires_at).toISOString();else body.expires_at=null;
  try{await api('/admin/api/overrides',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify(body)});form.reset();text(status,'Created.','success');await loadOverrides()}
  catch(error){text(status,error.message,'error')}};
async function loadPrivate(){const body=await api('/admin/api/private-projects');const root=document.querySelector('#private');
  root.replaceChildren();for(const project of body.projects){const row=document.createElement('p');
    row.textContent=`${project.normalized_name}: ${project.claimed_at?'privately owned':project.collisions.length?
      'public collision awaiting approval':'ready for first upload'}`;if(project.collisions.length&&!project.approved_at){
      const button=document.createElement('button');button.textContent='Acknowledge and approve';button.onclick=async()=>{
        await api(`/admin/api/private-projects/${project.normalized_name}/approve`,{method:'POST'});await loadPrivate()};
      row.append(' ',button)}root.append(row)}}
Promise.all([loadSettings(),loadOverrides(),loadPrivate()]).catch(error=>document.body.append(error.message));
</script></body></html>"""
