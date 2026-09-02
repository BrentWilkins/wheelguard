"""Provide persistent caching for upstream project metadata."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from wheelguard.database import Database
from wheelguard.models import (
    ProjectRepository,
    ProjectResponse,
    UpstreamNotFoundError,
    UpstreamRepositoryError,
)


class CachingRepository:
    """Cache project metadata and tolerate temporary upstream outages."""

    def __init__(
        self,
        upstream: ProjectRepository,
        database: Database,
        *,
        ttl: timedelta,
    ) -> None:
        """Initialize a caching facade around an upstream repository."""
        self._upstream = upstream
        self._database = database
        self._ttl = ttl

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        """Return fresh metadata or stale cached metadata during an outage."""
        now = datetime.now(UTC)
        cached = await self._database.get_project(normalized_name)
        if cached is not None and now - cached.fetched_at <= self._ttl:
            return cached.response
        try:
            fresh = await self._upstream.get_project(normalized_name)
        except (UpstreamNotFoundError, UpstreamRepositoryError):
            if cached is not None:
                return replace(cached.response, cache_status="STALE")
            raise
        await self._database.put_project(normalized_name, fresh, fetched_at=now)
        return replace(fresh, cache_status="MISS")

    async def aclose(self) -> None:
        """Close the wrapped repository when it exposes a close hook."""
        close = getattr(self._upstream, "aclose", None)
        if close is not None:
            await close()
