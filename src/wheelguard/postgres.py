"""PostgreSQL metadata catalog for horizontally scalable deployments."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import uuid4

import psycopg
from azure.identity.aio import DefaultAzureCredential
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from wheelguard.database import CachedAdvisories, CachedProject, _artifact_records
from wheelguard.models import ArtifactRecord, ProjectResponse, SimplePayload
from wheelguard.repository_tokens import RepositoryTokenRecord, issue_repository_token, repository_token_digest


class PostgresDatabase:
    """Persist repository state in Azure Database for PostgreSQL using Entra tokens."""

    def __init__(self, url: str, credential: DefaultAzureCredential, token_scope: str) -> None:
        self._url = url
        self._credential = credential
        self._token_scope = token_scope

    async def initialize(self) -> None:
        """Verify that the separately migrated schema is available."""
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT to_regclass('public.projects') AS projects, "
                "to_regclass('public.repository_tokens') AS repository_tokens"
            )
            row = await result.fetchone()
            if row is None or row["projects"] is None or row["repository_tokens"] is None:
                raise RuntimeError("PostgreSQL schema is not initialized; run wheelguard-migrate")

    async def health(self) -> None:
        async with self._connection() as connection:
            await connection.execute("SELECT 1")

    async def authenticate_repository_token(self, token: str) -> bool:
        """Validate one managed token and record its most recent use."""
        async with self._connection() as connection:
            result = await connection.execute(
                """
                WITH matched AS MATERIALIZED (
                    SELECT id FROM repository_tokens WHERE token_hash = %s AND revoked_at IS NULL
                ), touched AS (
                    UPDATE repository_tokens AS token SET last_used_at = now()
                    FROM matched
                    WHERE token.id = matched.id
                      AND (token.last_used_at IS NULL OR token.last_used_at < now() - interval '5 minutes')
                    RETURNING token.id
                )
                SELECT id FROM matched
                """,
                (repository_token_digest(token),),
            )
            authenticated = await result.fetchone() is not None
            await connection.commit()
            return authenticated

    async def create_repository_token(self, name: str, *, actor: str) -> str:
        """Create a named token and return its plaintext exactly once."""
        token = issue_repository_token()
        token_id = uuid4()
        async with self._connection() as connection:
            await connection.execute(
                "INSERT INTO repository_tokens (id, name, token_hash, created_by) VALUES (%s, %s, %s, %s)",
                (token_id, name.strip(), repository_token_digest(token), actor.strip()),
            )
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                "VALUES (%s, 'repository-token.created', %s, now(), %s)",
                (str(uuid4()), actor.strip(), Jsonb({"name": name.strip(), "token_id": str(token_id)})),
            )
            await connection.commit()
        return token

    async def list_repository_tokens(self) -> list[RepositoryTokenRecord]:
        """List token metadata without reading credential digests."""
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT name, created_at, created_by, last_used_at, revoked_at, revoked_by "
                "FROM repository_tokens ORDER BY name, created_at DESC"
            )
            return [RepositoryTokenRecord(**row) for row in await result.fetchall()]

    async def revoke_repository_token(self, name: str, *, actor: str) -> bool:
        """Revoke an active named token and append an audit event."""
        async with self._connection() as connection:
            result = await connection.execute(
                "UPDATE repository_tokens SET revoked_at = now(), revoked_by = %s "
                "WHERE name = %s AND revoked_at IS NULL RETURNING id",
                (actor.strip(), name.strip()),
            )
            row = await result.fetchone()
            if row is None:
                return False
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                "VALUES (%s, 'repository-token.revoked', %s, now(), %s)",
                (str(uuid4()), actor.strip(), Jsonb({"name": name.strip(), "token_id": str(row["id"])})),
            )
            await connection.commit()
            return True

    @asynccontextmanager
    async def _connection(self) -> AsyncIterator[psycopg.AsyncConnection[dict[str, Any]]]:
        token = await self._credential.get_token(self._token_scope)
        connection = await psycopg.AsyncConnection.connect(self._url, password=token.token, row_factory=dict_row)
        try:
            yield connection
        finally:
            await connection.close()

    async def get_project(self, normalized_name: str) -> CachedProject | None:
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT payload, last_serial, fetched_at FROM projects WHERE normalized_name = %s",
                (normalized_name,),
            )
            row = await result.fetchone()
        if row is None:
            return None
        return CachedProject(ProjectResponse(row["payload"], row["last_serial"], "HIT"), row["fetched_at"])

    async def put_project(self, normalized_name: str, response: ProjectResponse, *, fetched_at: datetime) -> None:
        async with self._connection() as connection:
            await connection.execute(
                """
                INSERT INTO projects (normalized_name, payload, last_serial, fetched_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(normalized_name) DO UPDATE SET
                    payload = excluded.payload, last_serial = excluded.last_serial, fetched_at = excluded.fetched_at
                """,
                (normalized_name, Jsonb(response.payload), response.last_serial, fetched_at),
            )
            await connection.commit()

    async def register_artifacts(self, project: str, payload: SimplePayload) -> None:
        records = list(_artifact_records(project, payload))
        if not records:
            return
        async with self._connection() as connection:
            async with connection.cursor() as cursor:
                await cursor.executemany(
                    """
                    INSERT INTO artifacts (sha256, filename, source_url, size, project, version, verification_sha256)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(sha256, filename) DO UPDATE SET
                        source_url = excluded.source_url, size = excluded.size,
                        project = excluded.project, version = excluded.version,
                        verification_sha256 = excluded.verification_sha256
                    """,
                    [
                        (r.sha256, r.filename, r.source_url, r.size, r.project, r.version, r.verification_sha256)
                        for r in records
                    ],
                )
            await connection.commit()

    async def get_artifact(self, sha256: str, filename: str) -> ArtifactRecord | None:
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT source_url, size, project, version, verification_sha256 FROM artifacts "
                "WHERE sha256 = %s AND filename = %s",
                (sha256, filename),
            )
            row = await result.fetchone()
        if row is None:
            return None
        return ArtifactRecord(
            sha256,
            filename,
            row["source_url"],
            row["size"],
            row["project"],
            row["version"],
            row["verification_sha256"],
        )

    async def list_projects(self) -> list[str]:
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT normalized_name FROM projects UNION SELECT normalized_name FROM private_projects "
                "WHERE claimed_at IS NOT NULL ORDER BY normalized_name"
            )
            return [row["normalized_name"] for row in await result.fetchall()]

    async def record_advisory_target(self, project: str, *, requested_at: datetime) -> None:
        async with self._connection() as connection:
            await connection.execute(
                "INSERT INTO advisory_targets (project, requested_at) VALUES (%s, %s) "
                "ON CONFLICT(project) DO UPDATE SET requested_at = excluded.requested_at",
                (project, requested_at),
            )
            await connection.commit()

    async def list_advisory_targets(self, *, requested_since: datetime, limit: int = 25) -> list[str]:
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT targets.project FROM advisory_targets AS targets WHERE targets.requested_at >= %s "
                "ORDER BY (SELECT MAX(checked_at) FROM advisory_scans WHERE project = targets.project) "
                "ASC NULLS FIRST, targets.requested_at ASC, targets.project ASC LIMIT %s",
                (requested_since, limit),
            )
            return [row["project"] for row in await result.fetchall()]

    async def prune_advisory_targets(self, *, requested_before: datetime) -> None:
        await self._execute("DELETE FROM advisory_targets WHERE requested_at < %s", (requested_before,))

    async def delete_advisory_target(self, project: str) -> None:
        await self._execute("DELETE FROM advisory_targets WHERE project = %s", (project,))

    async def get_advisories(self, project: str, versions_key: str) -> CachedAdvisories | None:
        return await self._one_advisory(
            "SELECT payload, checked_at FROM advisory_scans WHERE project = %s AND versions_key = %s",
            (project, versions_key),
        )

    async def get_latest_advisories(self, project: str) -> CachedAdvisories | None:
        return await self._one_advisory(
            "SELECT payload, checked_at FROM advisory_scans WHERE project = %s ORDER BY checked_at DESC LIMIT 1",
            (project,),
        )

    async def _one_advisory(self, query: str, values: tuple[object, ...]) -> CachedAdvisories | None:
        async with self._connection() as connection:
            result = await connection.execute(query, values)
            row = await result.fetchone()
        return None if row is None else CachedAdvisories(row["payload"], row["checked_at"])

    async def put_advisories(
        self,
        project: str,
        versions_key: str,
        advisories: dict[str, list[str]],
        *,
        checked_at: datetime,
    ) -> None:
        async with self._connection() as connection:
            await connection.execute(
                """
                INSERT INTO advisory_scans (project, versions_key, payload, checked_at) VALUES (%s, %s, %s, %s)
                ON CONFLICT(project, versions_key) DO UPDATE SET
                    payload = excluded.payload, checked_at = excluded.checked_at
                """,
                (project, versions_key, Jsonb(advisories), checked_at),
            )
            await connection.commit()

    async def _execute(self, query: str, values: tuple[object, ...]) -> None:
        async with self._connection() as connection:
            await connection.execute(query, values)
            await connection.commit()

    async def private_project(self, name: str) -> dict[str, Any] | None:
        async with self._connection() as connection:
            result = await connection.execute("SELECT * FROM private_projects WHERE normalized_name = %s", (name,))
            return await result.fetchone()

    async def record_private_collisions(self, name: str, collisions: list[str]) -> dict[str, Any]:
        async with self._connection() as connection:
            await connection.execute(
                """
                INSERT INTO private_projects (normalized_name, collisions) VALUES (%s, %s)
                ON CONFLICT(normalized_name) DO UPDATE SET collisions = excluded.collisions
                WHERE private_projects.claimed_at IS NULL AND private_projects.approved_at IS NULL
                    AND private_projects.collisions = '[]'::jsonb
                """,
                (name, Jsonb(collisions)),
            )
            result = await connection.execute("SELECT * FROM private_projects WHERE normalized_name = %s", (name,))
            row = await result.fetchone()
            await connection.commit()
        if row is None:
            raise RuntimeError("Private project catalog write failed")
        return row

    async def publish_private_artifact(
        self,
        *,
        project: str,
        filename: str,
        version: str,
        sha256: str,
        size: int,
        object_key: str,
        requires_python: str | None,
        repository_url: str | None,
        changelog_url: str | None,
        changelog: str | None,
        changelog_format: str | None,
        uploaded_at: datetime,
        actor: str,
    ) -> dict[str, Any] | None:
        from uuid import uuid4

        async with self._connection() as connection, connection.transaction():
            await connection.execute(
                """
                    INSERT INTO private_artifacts
                        (project, filename, version, sha256, size, object_key, requires_python, uploaded_at)
                    SELECT %s, %s, %s, %s, %s, %s, %s, %s FROM private_projects
                    WHERE normalized_name = %s
                        AND (collisions = '[]'::jsonb OR approved_at IS NOT NULL OR claimed_at IS NOT NULL)
                    ON CONFLICT(project, filename) DO NOTHING
                    """,
                (
                    project,
                    filename,
                    version,
                    sha256,
                    size,
                    object_key,
                    requires_python,
                    uploaded_at,
                    project,
                ),
            )
            await connection.execute(
                """
                    UPDATE private_projects
                    SET repository_url = COALESCE(%s, repository_url),
                        changelog_url = COALESCE(%s, changelog_url)
                    WHERE normalized_name = %s
                        AND EXISTS (
                            SELECT 1 FROM private_artifacts
                            WHERE project = %s AND filename = %s AND sha256 = %s
                        )
                    """,
                (repository_url, changelog_url, project, project, filename, sha256),
            )
            if changelog is not None and changelog_format is not None:
                await connection.execute(
                    """
                    INSERT INTO private_changelogs (project, version, content, format, updated_at, updated_by)
                    SELECT %s, %s, %s, %s, %s, %s
                    WHERE EXISTS (
                        SELECT 1 FROM private_artifacts
                        WHERE project = %s AND filename = %s AND sha256 = %s
                    )
                    ON CONFLICT(project, version) DO UPDATE SET
                        content = excluded.content,
                        format = excluded.format,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                    """,
                    (
                        project,
                        version,
                        changelog,
                        changelog_format,
                        uploaded_at,
                        actor,
                        project,
                        filename,
                        sha256,
                    ),
                )
            await connection.execute(
                """
                    UPDATE private_projects SET claimed_at = %s WHERE normalized_name = %s AND claimed_at IS NULL
                        AND EXISTS (SELECT 1 FROM private_artifacts WHERE project = %s)
                    """,
                (uploaded_at, project, project),
            )
            result = await connection.execute(
                "SELECT sha256, object_key FROM private_artifacts WHERE project = %s AND filename = %s",
                (project, filename),
            )
            row = await result.fetchone()
            if row is not None and row["object_key"] == object_key:
                await connection.execute(
                    """
                        INSERT INTO policy_audit (id, event_type, actor, occurred_at, details)
                        VALUES (%s, 'private.uploaded', %s, %s, %s)
                        """,
                    (
                        uuid4(),
                        actor,
                        uploaded_at,
                        Jsonb({"project": project, "filename": filename, "sha256": sha256}),
                    ),
                )
            return row

    async def private_artifacts(self, project: str) -> list[dict[str, Any]]:
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT filename, version, sha256, size, requires_python, uploaded_at, object_key "
                "FROM private_artifacts WHERE project = %s ORDER BY filename",
                (project,),
            )
            return list(await result.fetchall())

    async def private_project_versions(self) -> list[dict[str, Any]]:
        """List every published version for claimed private projects."""
        async with self._connection() as connection:
            result = await connection.execute(
                """
                SELECT p.normalized_name, a.version
                FROM private_projects p
                JOIN private_artifacts a ON a.project = p.normalized_name
                WHERE p.claimed_at IS NOT NULL
                ORDER BY p.normalized_name, a.version
                """
            )
            return list(await result.fetchall())

    async def private_changelog(self, project: str, version: str) -> dict[str, Any] | None:
        """Return the embedded changelog for one private release."""
        async with self._connection() as connection:
            result = await connection.execute(
                "SELECT content, format, updated_at, updated_by FROM private_changelogs "
                "WHERE project = %s AND version = %s",
                (project, version),
            )
            return await result.fetchone()

    async def set_private_changelog(
        self,
        project: str,
        version: str,
        content: str,
        changelog_format: str,
        actor: str,
        occurred_at: datetime,
    ) -> bool:
        """Upsert a bounded changelog for an existing release and audit it."""
        from uuid import uuid4

        async with self._connection() as connection, connection.transaction():
            changed = await connection.execute(
                """
                INSERT INTO private_changelogs (project, version, content, format, updated_at, updated_by)
                SELECT %s, %s, %s, %s, %s, %s
                WHERE EXISTS (SELECT 1 FROM private_artifacts WHERE project = %s AND version = %s)
                ON CONFLICT(project, version) DO UPDATE SET
                    content = excluded.content,
                    format = excluded.format,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (project, version, content, changelog_format, occurred_at, actor, project, version),
            )
            if changed.rowcount != 1:
                return False
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                "VALUES (%s, 'private.changelog-updated', %s, %s, %s)",
                (
                    uuid4(),
                    actor,
                    occurred_at,
                    Jsonb({"project": project, "version": version, "format": changelog_format}),
                ),
            )
            return True

    async def private_artifact(self, digest: str, filename: str) -> dict[str, Any] | None:
        async with self._connection() as connection:
            result = await connection.execute(
                """
                SELECT a.* FROM private_artifacts a JOIN private_projects p ON p.normalized_name = a.project
                WHERE a.sha256 = %s AND a.filename = %s AND p.claimed_at IS NOT NULL
                """,
                (digest, filename),
            )
            return await result.fetchone()

    async def active_overrides(self, project: str, now: datetime) -> dict[str, str]:
        async with self._connection() as connection:
            result = await connection.execute(
                """
                SELECT DISTINCT ON (version) version, action FROM policy_overrides
                WHERE project = %s AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > %s)
                ORDER BY version, created_at DESC
                """,
                (project, now),
            )
            return {row["version"]: row["action"] for row in await result.fetchall()}

    async def settings(self) -> dict[str, int | bool]:
        async with self._connection() as connection:
            result = await connection.execute("SELECT key, value FROM settings")
            return {row["key"]: row["value"] for row in await result.fetchall()}

    async def update_settings(self, updates: dict[str, int | bool], actor: str, occurred_at: datetime) -> None:
        from uuid import uuid4

        async with self._connection() as connection, connection.transaction():
            async with connection.cursor() as cursor:
                await cursor.executemany(
                    "INSERT INTO settings (key, value) VALUES (%s, %s) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [(key, Jsonb(value)) for key, value in updates.items()],
                )
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                "VALUES (%s, 'settings.updated', %s, %s, %s)",
                (uuid4(), actor, occurred_at, Jsonb({"updates": updates})),
            )

    async def reset_setting(self, key: str, actor: str, occurred_at: datetime) -> None:
        from uuid import uuid4

        async with self._connection() as connection, connection.transaction():
            await connection.execute("DELETE FROM settings WHERE key = %s", (key,))
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                "VALUES (%s, 'settings.reset', %s, %s, %s)",
                (uuid4(), actor, occurred_at, Jsonb({"reset": key})),
            )

    async def list_overrides(self) -> list[dict[str, Any]]:
        async with self._connection() as connection:
            result = await connection.execute("SELECT * FROM policy_overrides ORDER BY created_at DESC LIMIT 500")
            return list(await result.fetchall())

    async def create_override(
        self, override: Any, actor: str, occurred_at: datetime, *, replaces: str | None = None
    ) -> str:
        from uuid import UUID, uuid4

        identifier = uuid4()
        async with self._connection() as connection, connection.transaction():
            if replaces is not None:
                previous = UUID(replaces)
                changed = await connection.execute(
                    "UPDATE policy_overrides SET revoked_at = %s, revoked_by = %s, "
                    "revoke_reason = 'Replaced from admin UI' WHERE id = %s AND revoked_at IS NULL",
                    (occurred_at, actor, previous),
                )
                if changed.rowcount != 1:
                    raise KeyError("Active override not found")
                await connection.execute(
                    "INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details) "
                    "VALUES (%s, 'override.revoked', %s, %s, %s, %s)",
                    (uuid4(), actor, occurred_at, previous, Jsonb({"replacement_id": str(identifier)})),
                )
            await connection.execute(
                """
                    INSERT INTO policy_overrides
                        (id, project, version, action, reason, created_at, created_by, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                (
                    identifier,
                    override.project,
                    override.version,
                    override.action,
                    override.reason,
                    occurred_at,
                    actor,
                    override.expires_at,
                ),
            )
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details) "
                "VALUES (%s, 'override.created', %s, %s, %s, %s)",
                (
                    uuid4(),
                    actor,
                    occurred_at,
                    identifier,
                    Jsonb(
                        {
                            "project": override.project,
                            "version": override.version,
                            "action": override.action,
                            "reason": override.reason,
                            "expires_at": override.expires_at,
                            "replaces": replaces,
                        }
                    ),
                ),
            )
        return str(identifier)

    async def revoke_override(self, identifier: str, actor: str, occurred_at: datetime) -> None:
        from uuid import UUID, uuid4

        override_id = UUID(identifier)
        async with self._connection() as connection, connection.transaction():
            changed = await connection.execute(
                "UPDATE policy_overrides SET revoked_at = %s, revoked_by = %s, "
                "revoke_reason = 'Revoked from admin UI' WHERE id = %s AND revoked_at IS NULL",
                (occurred_at, actor, override_id),
            )
            if changed.rowcount != 1:
                raise KeyError("Active override not found")
            await connection.execute(
                "INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details) "
                "VALUES (%s, 'override.revoked', %s, %s, %s, '{}'::jsonb)",
                (uuid4(), actor, occurred_at, override_id),
            )

    async def list_private_projects(self) -> list[dict[str, Any]]:
        async with self._connection() as connection:
            result = await connection.execute("SELECT * FROM private_projects ORDER BY normalized_name")
            return list(await result.fetchall())

    async def approve_private_project(self, name: str, actor: str, occurred_at: datetime) -> bool:
        from uuid import uuid4

        async with self._connection() as connection, connection.transaction():
            result = await connection.execute(
                "SELECT collisions FROM private_projects WHERE normalized_name = %s FOR UPDATE", (name,)
            )
            row = await result.fetchone()
            if row is None or not row["collisions"]:
                return False
            changed = await connection.execute(
                "UPDATE private_projects SET approved_at = %s, approved_by = %s "
                "WHERE normalized_name = %s AND approved_at IS NULL",
                (occurred_at, actor, name),
            )
            if changed.rowcount == 1:
                await connection.execute(
                    "INSERT INTO policy_audit (id, event_type, actor, occurred_at, details) "
                    "VALUES (%s, 'private.collision-approved', %s, %s, %s)",
                    (uuid4(), actor, occurred_at, Jsonb({"project": name, "collisions": row["collisions"]})),
                )
            return True
