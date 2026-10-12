"""Run one advisory refresh batch as a scheduled Container Apps Job."""

import asyncio
from datetime import timedelta

from azure.identity.aio import DefaultAzureCredential

from wheelguard.advisories import OsvAdvisoryPolicy
from wheelguard.config import Settings
from wheelguard.postgres import PostgresDatabase
from wheelguard.refresh import AdvisoryRefresher


async def refresh() -> int:
    """Refresh recently used projects once and release all cloud clients."""
    settings = Settings.from_environment()
    if settings.database_url is None:
        raise SystemExit("WHEELGUARD_DATABASE_URL is required")
    credential = DefaultAzureCredential()
    database = PostgresDatabase(settings.database_url, credential, settings.database_token_scope)
    policy: OsvAdvisoryPolicy | None = None
    try:
        runtime = await database.settings()
        if not bool(runtime.get("osv_enabled", settings.osv_enabled)):
            return 0
        policy = OsvAdvisoryPolicy(
            database,
            url=settings.osv_url,
            ttl=timedelta(seconds=int(runtime.get("advisory_ttl_seconds", settings.advisory_ttl.total_seconds()))),
            timeout_seconds=settings.upstream_timeout_seconds,
        )
        refresher = AdvisoryRefresher(
            database,
            policy,
            active_window=timedelta(
                days=int(runtime.get("advisory_active_days", settings.advisory_active_window.days))
            ),
            batch_size=settings.advisory_refresh_batch_size,
        )
        return await refresher.refresh_once()
    finally:
        if policy is not None:
            await policy.aclose()
        await credential.close()


def main() -> None:
    """Run the scheduled refresh command."""
    print(f"refreshed={asyncio.run(refresh())}")  # noqa: T201


if __name__ == "__main__":
    main()
