"""Provider-neutral administrator operations for the FastAPI runtime."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from packaging.utils import canonicalize_name

from wheelguard.admin import parse_changelog_request, parse_override_request
from wheelguard.runtime_settings import SETTING_DEFINITIONS, parse_settings_update, setting_catalog


class AdminService:
    """Apply validated administrator changes and append audit records."""

    def __init__(self, database: Any, defaults: dict[str, int | bool]) -> None:
        self._database = database
        self._defaults = defaults

    async def settings(self) -> dict[str, object]:
        values = await self._database.settings()
        return {"settings": setting_catalog(self._defaults, values)}

    async def update_settings(self, body: Any, actor: str) -> dict[str, object]:
        serialized = parse_settings_update(body)
        updates = {
            key: value == "true" if SETTING_DEFINITIONS[key].kind == "boolean" else int(value)
            for key, value in serialized.items()
        }
        await self._database.update_settings(updates, actor, datetime.now(UTC))
        return await self.settings()

    async def reset_setting(self, key: str, actor: str) -> dict[str, object]:
        if key not in SETTING_DEFINITIONS:
            raise KeyError("Setting not found")
        await self._database.reset_setting(key, actor, datetime.now(UTC))
        return await self.settings()

    async def overrides(self) -> list[dict[str, object]]:
        return [_json_times(row) for row in await self._database.list_overrides()]

    async def create_override(self, body: Any, actor: str, *, replaces: str | None = None) -> dict[str, object]:
        override = parse_override_request(body)
        identifier = await self._database.create_override(override, actor, datetime.now(UTC), replaces=replaces)
        return {
            "id": identifier,
            "override": {
                "project": override.project,
                "version": override.version,
                "action": override.action,
                "reason": override.reason,
                "expires_at": override.expires_at,
            },
        }

    async def revoke_override(self, identifier: str, actor: str) -> None:
        await self._database.revoke_override(identifier, actor, datetime.now(UTC))

    async def private_projects(self) -> dict[str, object]:
        return {"projects": [_json_times(row) for row in await self._database.list_private_projects()]}

    async def approve_private_project(self, name: str, actor: str) -> dict[str, object]:
        try:
            if canonicalize_name(name, validate=True) != name:
                raise ValueError
        except ValueError as error:
            raise ValueError("Invalid normalized project name") from error
        if not await self._database.approve_private_project(name, actor, datetime.now(UTC)):
            raise KeyError("No pending public name collision for this project")
        return await self.private_projects()

    async def set_private_changelog(self, name: str, body: Any, actor: str) -> dict[str, object]:
        """Store a reviewed changelog snapshot for an existing private release."""
        try:
            normalized = canonicalize_name(name, validate=True)
        except ValueError as error:
            raise ValueError("Invalid package name") from error
        request = parse_changelog_request(body)
        if not await self._database.set_private_changelog(
            normalized,
            request.version,
            request.content,
            request.format,
            actor,
            datetime.now(UTC),
        ):
            raise KeyError("Published package version not found")
        return {"project": normalized, "version": request.version, "format": request.format}


def _json_times(row: dict[str, Any]) -> dict[str, object]:
    return {
        key: (
            value.isoformat().replace("+00:00", "Z")
            if isinstance(value, datetime)
            else str(value)
            if isinstance(value, UUID)
            else value
        )
        for key, value in row.items()
    }
