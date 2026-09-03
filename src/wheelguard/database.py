"""Persist project metadata and artifact records in SQLite."""

import asyncio
import json
import sqlite3
from collections.abc import Awaitable, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from wheelguard.models import ArtifactRecord, ProjectResponse, SimplePayload
from wheelguard.policy import filename_version

_DATABASE_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wheelguard-sqlite")


def _database_io[**P, R](operation: Callable[P, R]) -> Callable[P, Awaitable[R]]:
    """Run one blocking SQLite operation outside the event-loop thread."""

    async def offloaded(*args: P.args, **kwargs: P.kwargs) -> R:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_DATABASE_EXECUTOR, partial(operation, *args, **kwargs))

    return offloaded


@dataclass(frozen=True, slots=True)
class CachedProject:
    """Pair a cached project response with its retrieval timestamp."""

    response: ProjectResponse
    fetched_at: datetime


@dataclass(frozen=True, slots=True)
class CachedAdvisories:
    """Pair version advisory identifiers with their check timestamp."""

    advisories: dict[str, list[str]]
    checked_at: datetime


class Database:
    """Provide the persistent Wheelguard metadata catalog."""

    def __init__(self, path: Path) -> None:
        """Initialize a database located at ``path``."""
        self._path = path

    @_database_io
    def initialize(self) -> None:
        """Create the database directory and schema when absent."""
        self._initialize()

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    normalized_name TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    last_serial TEXT,
                    fetched_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    size INTEGER,
                    project TEXT,
                    version TEXT,
                    PRIMARY KEY (sha256, filename)
                );

            CREATE TABLE IF NOT EXISTS advisory_scans (
                project TEXT NOT NULL,
                versions_key TEXT NOT NULL,
                payload TEXT NOT NULL,
                checked_at REAL NOT NULL,
                PRIMARY KEY (project, versions_key)
            );

            CREATE TABLE IF NOT EXISTS advisory_targets (
                project TEXT PRIMARY KEY,
                requested_at REAL NOT NULL
            );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(artifacts)")}
            if "project" not in columns:
                connection.execute("ALTER TABLE artifacts ADD COLUMN project TEXT")
            if "version" not in columns:
                connection.execute("ALTER TABLE artifacts ADD COLUMN version TEXT")
            connection.execute("CREATE INDEX IF NOT EXISTS artifacts_release_lookup ON artifacts (project, version)")

    @_database_io
    def get_project(self, normalized_name: str) -> CachedProject | None:
        """Return cached project metadata by normalized name."""
        return self._get_project(normalized_name)

    def _get_project(self, normalized_name: str) -> CachedProject | None:
        with sqlite3.connect(self._path) as connection:
            row = connection.execute(
                "SELECT payload, last_serial, fetched_at FROM projects WHERE normalized_name = ?",
                (normalized_name,),
            ).fetchone()
        if row is None:
            return None
        payload: Any = json.loads(row[0])
        if not isinstance(payload, dict):
            return None
        return CachedProject(
            ProjectResponse(payload, row[1], "HIT"),
            datetime.fromtimestamp(row[2], tz=UTC),
        )

    @_database_io
    def put_project(
        self,
        normalized_name: str,
        response: ProjectResponse,
        *,
        fetched_at: datetime,
    ) -> None:
        """Persist project metadata and its artifact records."""
        self._put_project(normalized_name, response, fetched_at)

    def _put_project(
        self,
        normalized_name: str,
        response: ProjectResponse,
        fetched_at: datetime,
    ) -> None:
        encoded = json.dumps(response.payload, separators=(",", ":"), sort_keys=True)
        with sqlite3.connect(self._path) as connection:
            connection.execute(
                """
                INSERT INTO projects (normalized_name, payload, last_serial, fetched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(normalized_name) DO UPDATE SET
                    payload = excluded.payload,
                    last_serial = excluded.last_serial,
                    fetched_at = excluded.fetched_at
                """,
                (normalized_name, encoded, response.last_serial, fetched_at.timestamp()),
            )

    @_database_io
    def register_artifacts(self, project: str, payload: SimplePayload) -> None:
        """Register artifact locations discovered in a Simple API payload."""
        self._register_artifacts(project, payload)

    def _register_artifacts(self, project: str, payload: SimplePayload) -> None:
        records = list(_artifact_records(project, payload))
        if not records:
            return
        with sqlite3.connect(self._path) as connection:
            self._write_artifacts(connection, records)

    @staticmethod
    def _write_artifacts(connection: sqlite3.Connection, records: list[ArtifactRecord]) -> None:
        connection.executemany(
            """
                INSERT INTO artifacts (sha256, filename, source_url, size, project, version)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256, filename) DO UPDATE SET
                    source_url = excluded.source_url,
                    size = excluded.size,
                    project = excluded.project,
                    version = excluded.version
            """,
            [(r.sha256, r.filename, r.source_url, r.size, r.project, r.version) for r in records],
        )

    @_database_io
    def get_artifact(self, sha256: str, filename: str) -> ArtifactRecord | None:
        """Look up an artifact by digest and filename."""
        return self._get_artifact(sha256, filename)

    def _get_artifact(self, sha256: str, filename: str) -> ArtifactRecord | None:
        with sqlite3.connect(self._path) as connection:
            row = connection.execute(
                """
                SELECT source_url, size, project, version FROM artifacts
                WHERE sha256 = ? AND filename = ?
                """,
                (sha256, filename),
            ).fetchone()
        if row is None:
            return None
        return ArtifactRecord(sha256, filename, row[0], row[1], row[2], row[3])

    @_database_io
    def list_projects(self) -> list[str]:
        """List normalized names for all cached projects."""
        with sqlite3.connect(self._path) as connection:
            rows = connection.execute("SELECT normalized_name FROM projects ORDER BY normalized_name").fetchall()
        return [row[0] for row in rows]

    @_database_io
    def record_advisory_target(self, project: str, *, requested_at: datetime) -> None:
        """Record recent client interest in a project for periodic advisory refresh."""
        with sqlite3.connect(self._path) as connection:
            connection.execute(
                """
                INSERT INTO advisory_targets (project, requested_at)
                VALUES (?, ?)
                ON CONFLICT(project) DO UPDATE SET requested_at = excluded.requested_at
                """,
                (project, requested_at.timestamp()),
            )

    @_database_io
    def list_advisory_targets(self, *, requested_since: datetime, limit: int = 25) -> list[str]:
        """List projects requested within the active advisory window."""
        with sqlite3.connect(self._path) as connection:
            rows = connection.execute(
                """
                SELECT project FROM advisory_targets
                WHERE requested_at >= ?
                ORDER BY requested_at DESC
                LIMIT ?
                """,
                (requested_since.timestamp(), limit),
            ).fetchall()
        return [row[0] for row in rows]

    @_database_io
    def prune_advisory_targets(self, *, requested_before: datetime) -> None:
        """Delete advisory targets outside the active window."""
        with sqlite3.connect(self._path) as connection:
            connection.execute(
                "DELETE FROM advisory_targets WHERE requested_at < ?",
                (requested_before.timestamp(),),
            )

    @_database_io
    def delete_advisory_target(self, project: str) -> None:
        """Delete an advisory target that cannot be evaluated."""
        with sqlite3.connect(self._path) as connection:
            connection.execute("DELETE FROM advisory_targets WHERE project = ?", (project,))

    @_database_io
    def get_advisories(self, project: str, versions_key: str) -> CachedAdvisories | None:
        """Return a cached advisory result for an exact version set."""
        with sqlite3.connect(self._path) as connection:
            row = connection.execute(
                """
                SELECT payload, checked_at FROM advisory_scans
                WHERE project = ? AND versions_key = ?
                """,
                (project, versions_key),
            ).fetchone()
        if row is None:
            return None
        raw: Any = json.loads(row[0])
        if not isinstance(raw, dict):
            return None
        advisories = {
            version: [identifier for identifier in identifiers if isinstance(identifier, str)]
            for version, identifiers in raw.items()
            if isinstance(version, str) and isinstance(identifiers, list)
        }
        return CachedAdvisories(advisories, datetime.fromtimestamp(row[1], tz=UTC))

    @_database_io
    def get_latest_advisories(self, project: str) -> CachedAdvisories | None:
        """Return the newest cached advisory mapping for a project."""
        with sqlite3.connect(self._path) as connection:
            row = connection.execute(
                """
                SELECT payload, checked_at
                FROM advisory_scans
                WHERE project = ?
                ORDER BY checked_at DESC
                LIMIT 1
                """,
                (project,),
            ).fetchone()
        if row is None:
            return None
        raw: Any = json.loads(row[0])
        if not isinstance(raw, dict):
            return None
        advisories = {
            version: [identifier for identifier in identifiers if isinstance(identifier, str)]
            for version, identifiers in raw.items()
            if isinstance(version, str) and isinstance(identifiers, list)
        }
        return CachedAdvisories(advisories, datetime.fromtimestamp(row[1], tz=UTC))

    @_database_io
    def put_advisories(
        self,
        project: str,
        versions_key: str,
        advisories: dict[str, list[str]],
        *,
        checked_at: datetime,
    ) -> None:
        """Persist advisory identifiers for an exact project version set."""
        encoded = json.dumps(advisories, separators=(",", ":"), sort_keys=True)
        with sqlite3.connect(self._path) as connection:
            connection.execute(
                """
                INSERT INTO advisory_scans (project, versions_key, payload, checked_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(project, versions_key) DO UPDATE SET
                    payload = excluded.payload,
                    checked_at = excluded.checked_at
                """,
                (project, versions_key, encoded, checked_at.timestamp()),
            )


def _artifact_records(project: str, payload: SimplePayload) -> Iterator[ArtifactRecord]:
    files = payload.get("files", [])
    if not isinstance(files, list):
        return
    for file in files:
        if not isinstance(file, dict):
            continue
        hashes = file.get("hashes")
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        filename = file.get("filename")
        source_url = file.get("url")
        size = file.get("size")
        if not isinstance(digest, str) or not isinstance(filename, str) or not isinstance(source_url, str):
            continue
        version = filename_version(filename)
        yield ArtifactRecord(
            digest.casefold(),
            filename,
            source_url,
            size if isinstance(size, int) else None,
            project,
            str(version) if version is not None else None,
        )
