"""Apply publication-age policy to Simple API project metadata."""

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from wheelguard.models import SimplePayload


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """Summarize the payload and counts produced by policy evaluation."""

    payload: SimplePayload
    visible_files: int
    hidden_files: int


@dataclass(frozen=True, slots=True)
class MinimumAgePolicy:
    """Hide artifacts until they have aged beyond a configured interval."""

    minimum_age: timedelta
    allow_missing_upload_time: bool = True

    def apply(self, payload: SimplePayload, *, now: datetime) -> PolicyResult:
        """Filter artifacts that are newer than the configured minimum age."""
        if now.tzinfo is None:
            raise ValueError("now must include timezone information")
        result = deepcopy(payload)
        files = result.get("files", [])
        if not isinstance(files, list):
            files = []
        cutoff = now.astimezone(UTC) - self.minimum_age
        visible: list[Any] = []
        hidden_versions: set[Version] = set()
        visible_versions: set[Version] = set()
        for file in files:
            if not isinstance(file, dict):
                visible.append(file)
                continue
            version = filename_version(file.get("filename"))
            if self._visible(file.get("upload-time"), cutoff):
                visible.append(file)
                if version is not None:
                    visible_versions.add(version)
            elif version is not None:
                hidden_versions.add(version)
        result["files"] = visible
        versions = result.get("versions")
        if isinstance(versions, list):
            result["versions"] = [
                value for value in versions if not _only_hidden(value, hidden_versions, visible_versions)
            ]
        return PolicyResult(result, len(visible), len(files) - len(visible))

    def _visible(self, value: object, cutoff: datetime) -> bool:
        uploaded = _upload_time(value)
        return self.allow_missing_upload_time if uploaded is None else uploaded <= cutoff


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    """Apply administrator overrides before the configured publication-age rule."""

    minimum_age: timedelta
    allow_missing_upload_time: bool = True

    def apply(
        self,
        payload: SimplePayload,
        *,
        now: datetime,
        overrides: dict[str, str] | None = None,
    ) -> PolicyResult:
        """Filter release files, with explicit blocks winning and allows bypassing age."""
        if now.tzinfo is None:
            raise ValueError("now must include timezone information")
        actions = overrides or {}
        result = deepcopy(payload)
        files = result.get("files", [])
        if not isinstance(files, list):
            files = []
        cutoff = now.astimezone(UTC) - self.minimum_age
        visible: list[Any] = []
        hidden_versions: set[Version] = set()
        visible_versions: set[Version] = set()
        for file in files:
            if not isinstance(file, dict):
                visible.append(file)
                continue
            version = filename_version(file.get("filename"))
            action = actions.get(str(version)) if version is not None else None
            if action == "block":
                if version is not None:
                    hidden_versions.add(version)
                continue
            uploaded = _upload_time(file.get("upload-time"))
            age_allows = self.allow_missing_upload_time if uploaded is None else uploaded <= cutoff
            if action == "allow" or age_allows:
                visible.append(file)
                if version is not None:
                    visible_versions.add(version)
            elif version is not None:
                hidden_versions.add(version)
        result["files"] = visible
        versions = result.get("versions")
        if isinstance(versions, list):
            result["versions"] = [
                value for value in versions if not _only_hidden(value, hidden_versions, visible_versions)
            ]
        return PolicyResult(result, len(visible), len(files) - len(visible))


def _upload_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def filename_version(filename: object) -> Version | None:
    """Extract a normalized version from a wheel or source filename."""
    if not isinstance(filename, str):
        return None
    try:
        if filename.endswith(".whl"):
            return parse_wheel_filename(filename)[1]
        return parse_sdist_filename(filename)[1]
    except (InvalidSdistFilename, InvalidWheelFilename):
        return None


def _only_hidden(raw: object, hidden: set[Version], visible: set[Version]) -> bool:
    if not isinstance(raw, str):
        return False
    try:
        version = Version(raw)
    except InvalidVersion:
        return False
    return version in hidden and version not in visible
