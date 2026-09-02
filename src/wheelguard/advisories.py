"""Evaluate Python package versions against cached OSV advisories."""

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from wheelguard.database import Database
from wheelguard.models import AdvisoryResult, SimplePayload
from wheelguard.policy import filename_version

Clock = Callable[[], datetime]


class AdvisoryResponseError(Exception):
    """Indicate that an advisory service returned an invalid response."""


class NoopAdvisoryPolicy:
    """Leave project metadata unchanged when advisory checks are disabled."""

    async def apply(self, project: str, payload: SimplePayload) -> AdvisoryResult:
        """Return project metadata without advisory evaluation."""
        return AdvisoryResult(payload, "DISABLED")


class OsvAdvisoryPolicy:
    """Mark files from OSV-vulnerable releases as yanked."""

    def __init__(
        self,
        database: Database,
        *,
        url: str,
        ttl: timedelta,
        timeout_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Initialize an OSV policy with persistent result caching."""
        self._database = database
        self._url = url
        self._ttl = ttl
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def apply(self, project: str, payload: SimplePayload) -> AdvisoryResult:
        """Mark vulnerable files as yanked while preserving exact-pin access."""
        versions = _payload_versions(payload)
        if not versions:
            return AdvisoryResult(payload, "MISS")

        versions_key = _versions_key(versions)
        now = self._clock()
        cached = await self._database.get_advisories(project, versions_key)
        if cached is not None and now - cached.checked_at <= self._ttl:
            return _apply_advisories(payload, cached.advisories, "HIT")

        try:
            advisories = await self._query_versions(project, versions)
        except (httpx.HTTPError, AdvisoryResponseError):
            if cached is not None:
                return _apply_advisories(payload, cached.advisories, "STALE")
            return AdvisoryResult(payload, "ERROR")

        await self._database.put_advisories(
            project,
            versions_key,
            advisories,
            checked_at=now,
        )
        return _apply_advisories(payload, advisories, "MISS")

    async def aclose(self) -> None:
        """Close the owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()

    async def _query_versions(self, project: str, versions: list[str]) -> dict[str, list[str]]:
        advisories: dict[str, list[str]] = {}
        for offset in range(0, len(versions), 500):
            batch = versions[offset : offset + 500]
            response = await self._client.post(
                self._url,
                json={
                    "queries": [
                        {
                            "package": {"ecosystem": "PyPI", "name": project},
                            "version": version,
                        }
                        for version in batch
                    ]
                },
            )
            response.raise_for_status()
            results = _response_results(response.json(), len(batch))
            for version, result in zip(batch, results, strict=True):
                advisories[version] = _advisory_ids(result)
        return advisories


def _payload_versions(payload: SimplePayload) -> list[str]:
    files = payload.get("files", [])
    if not isinstance(files, list):
        return []
    versions = {
        str(version)
        for file in files
        if isinstance(file, dict) and (version := filename_version(file.get("filename"))) is not None
    }
    return sorted(versions)


def _versions_key(versions: list[str]) -> str:
    encoded = json.dumps(versions, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _response_results(raw: Any, expected: int) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        raise AdvisoryResponseError("OSV returned a non-object response")
    results = raw.get("results")
    if not isinstance(results, list) or len(results) != expected:
        raise AdvisoryResponseError("OSV returned an unexpected result count")
    if not all(isinstance(result, dict) for result in results):
        raise AdvisoryResponseError("OSV returned an invalid result")
    return results


def _advisory_ids(result: dict[str, Any]) -> list[str]:
    vulnerabilities = result.get("vulns", [])
    if not isinstance(vulnerabilities, list):
        raise AdvisoryResponseError("OSV returned an invalid vulnerability list")
    identifiers = {
        identifier
        for vulnerability in vulnerabilities
        if isinstance(vulnerability, dict) and isinstance((identifier := vulnerability.get("id")), str)
    }
    return sorted(identifiers)


def _apply_advisories(
    payload: SimplePayload,
    advisories: dict[str, list[str]],
    status: str,
) -> AdvisoryResult:
    result = deepcopy(payload)
    files = result.get("files", [])
    if not isinstance(files, list):
        return AdvisoryResult(result, status)

    vulnerable_files = 0
    for file in files:
        if not isinstance(file, dict):
            continue
        version = filename_version(file.get("filename"))
        identifiers = advisories.get(str(version), []) if version is not None else []
        if not identifiers:
            continue
        vulnerable_files += 1
        reason = f"Wheelguard advisories: {', '.join(identifiers)}"
        existing = file.get("yanked")
        if isinstance(existing, str) and existing:
            reason = f"{existing}; {reason}"
        file["yanked"] = reason
        file["wheelguard-advisories"] = identifiers
    return AdvisoryResult(result, status, vulnerable_files)
