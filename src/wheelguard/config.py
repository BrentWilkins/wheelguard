"""Load Wheelguard runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    """Describe immutable Wheelguard runtime settings."""

    upstream_url: str = "https://pypi.org/simple/"
    minimum_age: timedelta = timedelta(days=14)
    upstream_timeout_seconds: float = 30.0
    allow_missing_upload_time: bool = True
    data_dir: Path = Path(".wheelguard-data")
    metadata_ttl: timedelta = timedelta(minutes=5)
    maximum_artifact_bytes: int = 100 * 1024 * 1024
    osv_enabled: bool = False
    osv_url: str = "https://api.osv.dev/v1/querybatch"
    advisory_ttl: timedelta = timedelta(hours=6)
    advisory_refresh_interval: timedelta = timedelta(hours=1)
    advisory_active_window: timedelta = timedelta(days=30)
    auth_token: str | None = None

    @classmethod
    def from_environment(cls) -> Settings:
        """Build settings from ``WHEELGUARD_*`` environment variables."""
        return cls(
            upstream_url=os.getenv("WHEELGUARD_UPSTREAM_URL", "https://pypi.org/simple/"),
            minimum_age=timedelta(days=int(os.getenv("WHEELGUARD_MINIMUM_AGE_DAYS", "14"))),
            upstream_timeout_seconds=float(os.getenv("WHEELGUARD_UPSTREAM_TIMEOUT", "30")),
            allow_missing_upload_time=os.getenv("WHEELGUARD_ALLOW_MISSING_UPLOAD_TIME", "true").casefold()
            in {"1", "true", "yes", "on"},
            data_dir=Path(os.getenv("WHEELGUARD_DATA_DIR", ".wheelguard-data")),
            metadata_ttl=timedelta(seconds=int(os.getenv("WHEELGUARD_METADATA_TTL_SECONDS", "300"))),
            maximum_artifact_bytes=int(os.getenv("WHEELGUARD_MAXIMUM_ARTIFACT_BYTES", str(100 * 1024 * 1024))),
            osv_enabled=os.getenv("WHEELGUARD_OSV_ENABLED", "false").casefold() in {"1", "true", "yes", "on"},
            osv_url=os.getenv("WHEELGUARD_OSV_URL", "https://api.osv.dev/v1/querybatch"),
            advisory_ttl=timedelta(seconds=int(os.getenv("WHEELGUARD_ADVISORY_TTL_SECONDS", "21600"))),
            advisory_refresh_interval=timedelta(seconds=int(os.getenv("WHEELGUARD_ADVISORY_REFRESH_SECONDS", "3600"))),
            advisory_active_window=timedelta(days=int(os.getenv("WHEELGUARD_ADVISORY_ACTIVE_DAYS", "30"))),
            auth_token=os.getenv("WHEELGUARD_AUTH_TOKEN") or None,
        )
