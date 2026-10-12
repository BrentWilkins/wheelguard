"""Validate administrator policy-override requests."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version


class InvalidOverrideError(ValueError):
    """Indicate that an override request is malformed."""


CHANGELOG_LIMIT = 256 * 1024


@dataclass(frozen=True, slots=True)
class ChangelogRequest:
    """Describe a bounded changelog snapshot for one published version."""

    version: str
    content: str
    format: str


def parse_changelog_request(raw: Any) -> ChangelogRequest:
    """Validate an administrator-supplied release changelog snapshot."""
    if not isinstance(raw, dict):
        raise ValueError("Request body must be a JSON object")
    version, content, changelog_format = raw.get("version"), raw.get("content"), raw.get("format", "markdown")
    if not isinstance(version, str):
        raise ValueError("version is required")
    try:
        normalized_version = str(Version(version.strip()))
    except InvalidVersion as error:
        raise ValueError("version is not a valid Python package version") from error
    if not isinstance(content, str) or not content.strip():
        raise ValueError("content is required")
    if len(content.encode("utf-8")) > CHANGELOG_LIMIT:
        raise ValueError("content must be 256 KiB or smaller")
    if changelog_format not in {"markdown", "rst", "text"}:
        raise ValueError("format must be markdown, rst, or text")
    return ChangelogRequest(normalized_version, content, changelog_format)


def admin_content_security_policy(nonce: str) -> str:
    """Return the administrator page policy, including same-origin API access."""
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )


@dataclass(frozen=True, slots=True)
class OverrideRequest:
    """Describe a validated release-policy override."""

    project: str
    version: str
    action: str
    reason: str
    expires_at: str | None


def parse_override_request(raw: Any) -> OverrideRequest:
    """Validate and normalize an administrator override request."""
    if not isinstance(raw, dict):
        raise InvalidOverrideError("Request body must be a JSON object")

    project = raw.get("project")
    version = raw.get("version")
    action = raw.get("action")
    reason = raw.get("reason")
    expires_at = raw.get("expires_at")

    if not isinstance(project, str) or not project.strip():
        raise InvalidOverrideError("project is required")
    project = project.strip()
    if len(project) > 200:
        raise InvalidOverrideError("project must be 200 characters or fewer")
    try:
        normalized_project = canonicalize_name(project, validate=True)
    except InvalidName as error:
        raise InvalidOverrideError("project is not a valid Python package name") from error

    if not isinstance(version, str) or not version.strip():
        raise InvalidOverrideError("version is required")
    version = version.strip()
    if len(version) > 200:
        raise InvalidOverrideError("version must be 200 characters or fewer")
    try:
        normalized_version = str(Version(version))
    except InvalidVersion as error:
        raise InvalidOverrideError("version is not a valid Python package version") from error

    if action not in {"allow", "block"}:
        raise InvalidOverrideError("action must be either 'allow' or 'block'")
    if not isinstance(reason, str) or not reason.strip():
        raise InvalidOverrideError("reason is required")
    reason = reason.strip()
    if len(reason) > 500:
        raise InvalidOverrideError("reason must be 500 characters or fewer")

    normalized_expiry = _parse_expiry(expires_at)
    return OverrideRequest(
        project=normalized_project,
        version=normalized_version,
        action=action,
        reason=reason,
        expires_at=normalized_expiry,
    )


def _parse_expiry(raw: Any) -> str | None:
    """Return a normalized UTC expiry timestamp when supplied."""
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise InvalidOverrideError("expires_at must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise InvalidOverrideError("expires_at must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise InvalidOverrideError("expires_at must include a timezone")
    parsed = parsed.astimezone(UTC)
    if parsed <= datetime.now(UTC):
        raise InvalidOverrideError("expires_at must be in the future")
    return parsed.isoformat().replace("+00:00", "Z")
