"""Provide persistent caching for upstream project metadata."""

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from time import perf_counter

from wheelguard.database import Database
from wheelguard.models import (
    ProjectRepository,
    ProjectResponse,
    UpstreamNotFoundError,
    UpstreamRepositoryError,
)

LOGGER = logging.getLogger("uvicorn.error")


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

    async def get_project(self, normalized_name: str, *, ttl: timedelta | None = None) -> ProjectResponse:
        """Return fresh metadata or stale cached metadata during an outage."""
        started = perf_counter()
        now = datetime.now(UTC)
        cached = await self._database.get_project(normalized_name)
        cache_lookup_ms = (perf_counter() - started) * 1_000
        if cached is not None and now - cached.fetched_at <= (ttl or self._ttl):
            LOGGER.info(
                "metadata.timing project=%s cache=hit cache_lookup_ms=%.1f upstream_ms=0.0 database_write_ms=0.0 "
                "total_ms=%.1f",
                normalized_name,
                cache_lookup_ms,
                (perf_counter() - started) * 1_000,
            )
            return cached.response
        upstream_started = perf_counter()
        try:
            fresh = await self._upstream.get_project(normalized_name)
        except (UpstreamNotFoundError, UpstreamRepositoryError):
            if cached is not None:
                LOGGER.info(
                    "metadata.timing project=%s cache=stale cache_lookup_ms=%.1f upstream_ms=%.1f "
                    "database_write_ms=0.0 total_ms=%.1f",
                    normalized_name,
                    cache_lookup_ms,
                    (perf_counter() - upstream_started) * 1_000,
                    (perf_counter() - started) * 1_000,
                )
                return replace(cached.response, cache_status="STALE")
            raise
        upstream_ms = (perf_counter() - upstream_started) * 1_000
        write_started = perf_counter()
        await self._database.put_project(normalized_name, fresh, fetched_at=now)
        database_write_ms = (perf_counter() - write_started) * 1_000
        LOGGER.info(
            "metadata.timing project=%s cache=miss cache_lookup_ms=%.1f upstream_ms=%.1f database_write_ms=%.1f "
            "total_ms=%.1f",
            normalized_name,
            cache_lookup_ms,
            upstream_ms,
            database_write_ms,
            (perf_counter() - started) * 1_000,
        )
        return replace(fresh, cache_status="MISS")

    async def aclose(self) -> None:
        """Close the wrapped repository when it exposes a close hook."""
        close = getattr(self._upstream, "aclose", None)
        if close is not None:
            await close()
