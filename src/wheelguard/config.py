"""Load and validate Wheelguard runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit


def _boolean(name: str, default: str) -> bool:
    """Parse one environment boolean."""
    value = os.getenv(name, default).casefold()
    if value not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"1", "true", "yes", "on"}


def _integer(name: str, default: str) -> int:
    """Parse an environment integer with display separators."""
    return int(os.getenv(name, default).replace(",", "").replace("_", ""))


@dataclass(frozen=True, slots=True)
class Settings:
    """Describe immutable Wheelguard runtime settings."""

    upstream_url: str = "https://pypi.org/simple/"
    public_url: str | None = None
    minimum_age: timedelta = timedelta(days=14)
    fallback_minimum_age: timedelta = timedelta(hours=24)
    upstream_timeout_seconds: float = 30.0
    allow_missing_upload_time: bool = False
    allowed_artifact_hosts: frozenset[str] = frozenset({"files.pythonhosted.org"})
    data_dir: Path = Path(".wheelguard-data")
    metadata_ttl: timedelta = timedelta(minutes=5)
    maximum_artifact_bytes: int = 100 * 1024 * 1024
    osv_enabled: bool = False
    osv_url: str = "https://api.osv.dev/v1/querybatch"
    advisory_ttl: timedelta = timedelta(hours=6)
    advisory_refresh_interval: timedelta = timedelta(hours=1)
    advisory_active_window: timedelta = timedelta(days=30)
    advisory_refresh_batch_size: int = 25
    auth_token: str | None = None
    auth_tokens: tuple[str, ...] = ()
    admin_token: str | None = None
    admin_token_actor: str = "temporary-admin"
    managed_token_auth_enabled: bool = False
    database_url: str | None = None
    database_token_scope: str = "https://ossrdbms-aad.database.windows.net/.default"
    database_app_principal: str | None = None
    database_app_object_id: str | None = None
    azure_storage_account_url: str | None = None
    azure_artifact_container: str = "artifacts"
    publisher_oidc_issuer: str | None = None
    publisher_oidc_audience: str = "wheelguard-publisher"
    publisher_oidc_projects: tuple[str, ...] = ()
    entra_admin_enabled: bool = False
    trust_private_ingress: bool = False

    def __post_init__(self) -> None:
        """Reject unsafe remote endpoints and empty artifact allowlists."""
        upstream = urlsplit(self.upstream_url)
        if upstream.scheme != "https" or not upstream.hostname:
            raise ValueError("WHEELGUARD_UPSTREAM_URL must be an HTTPS URL")
        if self.public_url is not None:
            public = urlsplit(self.public_url)
            if (
                public.scheme not in {"http", "https"}
                or not public.hostname
                or public.username is not None
                or public.password is not None
                or public.path not in {"", "/"}
                or public.query
                or public.fragment
            ):
                raise ValueError("WHEELGUARD_PUBLIC_URL must be an HTTP(S) origin without credentials or a path")
        if not self.allowed_artifact_hosts:
            raise ValueError("WHEELGUARD_ALLOWED_ARTIFACT_HOSTS cannot be empty")
        if self.osv_enabled:
            osv = urlsplit(self.osv_url)
            if osv.scheme != "https" or not osv.hostname:
                raise ValueError("WHEELGUARD_OSV_URL must be an HTTPS URL")
        if (self.database_app_principal is None) != (self.database_app_object_id is None):
            raise ValueError(
                "WHEELGUARD_DATABASE_APP_PRINCIPAL and WHEELGUARD_DATABASE_APP_OBJECT_ID must be configured together"
            )

    @classmethod
    def from_environment(cls) -> Settings:
        """Build settings from ``WHEELGUARD_*`` environment variables."""
        hosts = frozenset(
            host.strip().casefold()
            for host in os.getenv("WHEELGUARD_ALLOWED_ARTIFACT_HOSTS", "files.pythonhosted.org").split(",")
            if host.strip()
        )
        return cls(
            upstream_url=os.getenv("WHEELGUARD_UPSTREAM_URL", "https://pypi.org/simple/"),
            public_url=os.getenv("WHEELGUARD_PUBLIC_URL") or None,
            minimum_age=timedelta(days=_integer("WHEELGUARD_MINIMUM_AGE_DAYS", "14")),
            fallback_minimum_age=timedelta(hours=_integer("WHEELGUARD_FALLBACK_MINIMUM_AGE_HOURS", "24")),
            upstream_timeout_seconds=float(os.getenv("WHEELGUARD_UPSTREAM_TIMEOUT", "30")),
            allow_missing_upload_time=_boolean("WHEELGUARD_ALLOW_MISSING_UPLOAD_TIME", "false"),
            allowed_artifact_hosts=hosts,
            data_dir=Path(os.getenv("WHEELGUARD_DATA_DIR", ".wheelguard-data")),
            metadata_ttl=timedelta(seconds=_integer("WHEELGUARD_METADATA_TTL_SECONDS", "300")),
            maximum_artifact_bytes=_integer("WHEELGUARD_MAXIMUM_ARTIFACT_BYTES", str(100 * 1024 * 1024)),
            osv_enabled=_boolean("WHEELGUARD_OSV_ENABLED", "false"),
            osv_url=os.getenv("WHEELGUARD_OSV_URL", "https://api.osv.dev/v1/querybatch"),
            advisory_ttl=timedelta(seconds=_integer("WHEELGUARD_ADVISORY_TTL_SECONDS", "21600")),
            advisory_refresh_interval=timedelta(seconds=_integer("WHEELGUARD_ADVISORY_REFRESH_SECONDS", "3600")),
            advisory_active_window=timedelta(days=_integer("WHEELGUARD_ADVISORY_ACTIVE_DAYS", "30")),
            advisory_refresh_batch_size=_integer("WHEELGUARD_ADVISORY_REFRESH_BATCH_SIZE", "25"),
            auth_token=os.getenv("WHEELGUARD_AUTH_TOKEN") or None,
            auth_tokens=tuple(
                token.strip() for token in os.getenv("WHEELGUARD_AUTH_TOKENS", "").split(",") if token.strip()
            ),
            admin_token=os.getenv("WHEELGUARD_ADMIN_TOKEN") or None,
            admin_token_actor=os.getenv("WHEELGUARD_ADMIN_TOKEN_ACTOR", "temporary-admin").strip() or "temporary-admin",
            managed_token_auth_enabled=_boolean("WHEELGUARD_MANAGED_TOKEN_AUTH_ENABLED", "false"),
            database_url=os.getenv("WHEELGUARD_DATABASE_URL") or None,
            database_token_scope=os.getenv(
                "WHEELGUARD_DATABASE_TOKEN_SCOPE", "https://ossrdbms-aad.database.windows.net/.default"
            ),
            database_app_principal=os.getenv("WHEELGUARD_DATABASE_APP_PRINCIPAL") or None,
            database_app_object_id=os.getenv("WHEELGUARD_DATABASE_APP_OBJECT_ID") or None,
            azure_storage_account_url=os.getenv("WHEELGUARD_AZURE_STORAGE_ACCOUNT_URL") or None,
            azure_artifact_container=os.getenv("WHEELGUARD_AZURE_ARTIFACT_CONTAINER", "artifacts"),
            publisher_oidc_issuer=os.getenv("WHEELGUARD_PUBLISHER_OIDC_ISSUER") or None,
            publisher_oidc_audience=os.getenv("WHEELGUARD_PUBLISHER_OIDC_AUDIENCE", "wheelguard-publisher"),
            publisher_oidc_projects=tuple(
                project.strip()
                for project in os.getenv("WHEELGUARD_PUBLISHER_OIDC_PROJECTS", "").split(",")
                if project.strip()
            ),
            entra_admin_enabled=_boolean("WHEELGUARD_ENTRA_ADMIN_ENABLED", "false"),
            trust_private_ingress=_boolean("WHEELGUARD_TRUST_PRIVATE_INGRESS", "false"),
        )
