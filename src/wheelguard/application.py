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
from urllib.parse import quote

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from packaging.utils import canonicalize_name
from starlette.middleware.base import RequestResponseEndpoint

from wheelguard.admin import InvalidOverrideError, admin_content_security_policy
from wheelguard.admin_service import AdminService
from wheelguard.advisories import NoopAdvisoryPolicy, OsvAdvisoryPolicy
from wheelguard.artifacts import ArtifactService, FileArtifactStore
from wheelguard.auth import TokenAuthenticator, authorization_token
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
            return HTMLResponse(render_project_html(payload), media_type=SIMPLE_HTML, headers=headers)
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
        return HTMLResponse(render_project_html(published), media_type=SIMPLE_HTML, headers=headers)

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
        raise IdentityError("Administrator authentication required")

    def admin_denied(error: IdentityError) -> JSONResponse:
        headers = (
            {"WWW-Authenticate": 'Basic realm="Wheelguard administration"'} if admin_authenticator.enabled else None
        )
        return JSONResponse({"detail": str(error)}, status_code=401 if headers else 403, headers=headers)

    @application.get("/admin/")
    async def admin_page(request: Request) -> Response:
        try:
            actor, _ = administrator(request)
        except IdentityError as error:
            return admin_denied(error)
        nonce = secrets.token_urlsafe(24)
        body = _ADMIN_PAGE.replace("{{ actor }}", html.escape(actor)).replace("{{ nonce }}", nonce)
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
            _same_origin(request)
            return JSONResponse(await service.update_settings(await _json_body(request), actor))
        except IdentityError as error:
            return admin_denied(error)
        except (InvalidSettingsError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

    @application.delete("/admin/api/settings/{key}")
    async def admin_reset_setting(key: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request)
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
            _same_origin(request)
            return JSONResponse(await service.create_override(await _json_body(request), actor), status_code=201)
        except IdentityError as error:
            return admin_denied(error)
        except (InvalidOverrideError, ValueError) as error:
            return JSONResponse({"detail": str(error)}, status_code=422)

    @application.patch("/admin/api/overrides/{identifier}")
    async def admin_replace_override(identifier: str, request: Request) -> Response:
        try:
            actor, service = administrator(request)
            _same_origin(request)
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
            _same_origin(request)
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
            _same_origin(request)
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


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    fetch_site = (request.headers.get("sec-fetch-site") or "").casefold()
    expected = f"{request.url.scheme}://{request.url.netloc}"
    if origin == expected or (origin is None and fetch_site == "same-origin"):
        return
    raise IdentityError("Cross-origin administrator writes are not allowed")


_ADMIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wheelguard administration</title><style>
:root{color-scheme:light dark}body{font:16px/1.5 system-ui;max-width:70rem;margin:2rem auto;padding:0 1rem}
form,.settings{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:1rem}
label{display:grid;gap:.3rem}input,select,button{font:inherit;padding:.55rem}.wide{grid-column:1/-1}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid GrayText;padding:.6rem;text-align:left}
.scroll{overflow:auto}.error{color:#d33}.success{color:#187b36}.setting{border:1px solid GrayText;padding:.7rem}
</style></head><body>
<h1>Wheelguard administration</h1><p>Signed in as <strong>{{ actor }}</strong>.</p>
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
