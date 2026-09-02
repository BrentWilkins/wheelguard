"""Evaluate OSV results and choose safe release-policy fallbacks."""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from packaging.version import Version

from wheelguard.models import SimplePayload
from wheelguard.policy import filename_version


class InvalidOsvResponseError(ValueError):
    """Indicate that OSV returned a malformed response document."""


def payload_versions(payload: SimplePayload) -> list[str]:
    """Return sorted unique normalized versions represented by project files."""
    files = payload.get("files", [])
    if not isinstance(files, list):
        return []
    versions = {
        str(version)
        for file in files
        if isinstance(file, dict) and (version := filename_version(file.get("filename"))) is not None
    }
    return sorted(versions, key=Version)


def versions_key(versions: list[str]) -> str:
    """Build a stable cache key for a set of queried versions."""
    encoded = json.dumps(versions, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def parse_osv_results(raw: Any, versions: list[str]) -> dict[str, list[str]]:
    """Validate an OSV querybatch response and map versions to advisory identifiers."""
    if not isinstance(raw, dict):
        raise InvalidOsvResponseError("OSV returned a non-object response")
    results = raw.get("results")
    if not isinstance(results, list) or len(results) != len(versions):
        raise InvalidOsvResponseError("OSV returned an unexpected result count")
    advisories: dict[str, list[str]] = {}
    for version, result in zip(versions, results, strict=True):
        if not isinstance(result, dict):
            raise InvalidOsvResponseError("OSV returned an invalid result")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise InvalidOsvResponseError("OSV returned an invalid vulnerability list")
        identifiers = {
            identifier
            for vulnerability in vulnerabilities
            if isinstance(vulnerability, dict) and isinstance((identifier := vulnerability.get("id")), str)
        }
        advisories[version] = sorted(identifiers)
    return advisories


def apply_advisories(payload: SimplePayload, advisories: dict[str, list[str]]) -> SimplePayload:
    """Mark known-vulnerable files as yanked while retaining exact-pin access."""
    result = deepcopy(payload)
    files = result.get("files", [])
    if not isinstance(files, list):
        return result
    for file in files:
        if not isinstance(file, dict):
            continue
        version = filename_version(file.get("filename"))
        identifiers = advisories.get(str(version), []) if version is not None else []
        if not identifiers:
            continue
        reason = f"Wheelguard advisories: {', '.join(identifiers)}"
        existing = file.get("yanked")
        if isinstance(existing, str) and existing:
            reason = f"{existing}; {reason}"
        file["yanked"] = reason
        file["wheelguard-advisories"] = identifiers
    return result


def automatic_fixed_version_allows(
    payload: SimplePayload,
    advisories: dict[str, list[str]],
    *,
    now: datetime,
    minimum_age: timedelta,
) -> dict[str, str]:
    """Allow the newest fresh fixed release when every aged candidate is known vulnerable."""
    if now.tzinfo is None:
        raise ValueError("now must include timezone information")
    if not any(advisories.values()):
        return {}
    files = payload.get("files", [])
    if not isinstance(files, list):
        return {}
    cutoff = now.astimezone(UTC) - minimum_age
    aged_safe: set[Version] = set()
    fresh_safe: set[Version] = set()
    for file in files:
        if not isinstance(file, dict):
            continue
        version = filename_version(file.get("filename"))
        if version is None or advisories.get(str(version)):
            continue
        uploaded = _upload_time(file.get("upload-time"))
        if uploaded is None or uploaded <= cutoff:
            aged_safe.add(version)
        else:
            fresh_safe.add(version)
    if aged_safe or not fresh_safe:
        return {}
    newest = max(fresh_safe)
    return {str(newest): "allow"}


def _upload_time(value: object) -> datetime | None:
    """Parse a PEP 700 upload timestamp."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)
