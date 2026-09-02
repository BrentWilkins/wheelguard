"""Periodically refresh advisories for recently requested projects."""

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from wheelguard.database import Database
from wheelguard.models import AdvisoryPolicy

Clock = Callable[[], datetime]
LOGGER = logging.getLogger(__name__)


class AdvisoryRefresher:
    """Refresh cached advisory results for active projects."""

    def __init__(
        self,
        database: Database,
        advisory_policy: AdvisoryPolicy,
        *,
        active_window: timedelta,
        batch_size: int = 25,
        clock: Clock | None = None,
    ) -> None:
        """Initialize a refresher over the persistent project catalog."""
        self._database = database
        self._advisory_policy = advisory_policy
        self._active_window = active_window
        self._batch_size = batch_size
        self._clock = clock or (lambda: datetime.now(UTC))

    async def refresh_once(self) -> int:
        """Refresh advisories once and return the number of evaluated projects."""
        now = self._clock()
        cutoff = now - self._active_window
        targets = await self._database.list_advisory_targets(requested_since=cutoff, limit=self._batch_size)
        await self._database.prune_advisory_targets(requested_before=cutoff)
        evaluated = 0
        for project in targets:
            cached = await self._database.get_project(project)
            if cached is None:
                await self._database.delete_advisory_target(project)
                continue
            result = await self._advisory_policy.apply(project, cached.response.payload)
            if result.vulnerable_files:
                LOGGER.warning(
                    "Advisory refresh found %d vulnerable files for %s",
                    result.vulnerable_files,
                    project,
                )
            evaluated += 1
        return evaluated

    async def run(self, interval: timedelta) -> None:
        """Refresh active projects repeatedly until the task is cancelled."""
        seconds = interval.total_seconds()
        if seconds <= 0:
            return
        while True:
            await asyncio.sleep(seconds)
            try:
                await self.refresh_once()
            except Exception:
                LOGGER.exception("Periodic advisory refresh failed")
