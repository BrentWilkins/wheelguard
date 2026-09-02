"""Validate administrator-editable runtime policy settings."""

from dataclasses import dataclass
from typing import Any


class InvalidSettingsError(ValueError):
    """Indicate that a runtime settings update is malformed."""


@dataclass(frozen=True, slots=True)
class SettingDefinition:
    """Describe one editable setting and its validation rules."""

    kind: str
    minimum: int | None
    maximum: int | None
    label: str
    description: str


SETTING_DEFINITIONS = {
    "minimum_age_days": SettingDefinition(
        "integer",
        1,
        365,
        "Minimum release age (days)",
        "Hide new releases for this many days unless a bounded safety fallback or explicit allow applies.",
    ),
    "fallback_minimum_age_hours": SettingDefinition(
        "integer",
        1,
        336,
        "Safety fallback minimum age (hours)",
        "Never auto-allow a fixed release until it has reached this age.",
    ),
    "allow_missing_upload_time": SettingDefinition(
        "boolean",
        None,
        None,
        "Allow missing upload timestamps",
        "Allow files without a PEP 700 upload timestamp. Disable this for a strict fail-closed policy.",
    ),
    "metadata_ttl_seconds": SettingDefinition(
        "integer",
        1,
        86_400,
        "Metadata cache lifetime (seconds)",
        "Refresh upstream project metadata after this interval.",
    ),
    "maximum_artifact_bytes": SettingDefinition(
        "integer",
        1,
        104_857_600,
        "Per-artifact download limit (bytes)",
        "Reject larger distributions before they enter R2 (maximum 100 MiB for bounded Worker memory use).",
    ),
    "osv_enabled": SettingDefinition(
        "boolean",
        None,
        None,
        "OSV vulnerability policy",
        "Check requested versions and periodically rescan active projects.",
    ),
    "advisory_ttl_seconds": SettingDefinition(
        "integer",
        60,
        604_800,
        "Advisory cache lifetime (seconds)",
        "Reuse a successful OSV result for this interval on request paths.",
    ),
    "advisory_active_days": SettingDefinition(
        "integer",
        1,
        365,
        "Active-project window (days)",
        "Keep periodically scanning projects requested within this window.",
    ),
}


def parse_settings_update(raw: Any) -> dict[str, str]:
    """Validate a partial settings object and serialize it for D1."""
    if not isinstance(raw, dict):
        raise InvalidSettingsError("Request body must be a JSON object")
    if not raw:
        raise InvalidSettingsError("At least one setting is required")
    unknown = sorted(set(raw) - SETTING_DEFINITIONS.keys())
    if unknown:
        raise InvalidSettingsError(f"Unknown setting: {unknown[0]}")
    return {key: _serialize_value(key, value) for key, value in raw.items()}


def decode_stored_settings(rows: object) -> dict[str, int | bool]:
    """Decode valid D1 setting rows while ignoring unknown or corrupt entries."""
    if not isinstance(rows, list):
        return {}
    result: dict[str, int | bool] = {}
    for row in rows:
        if not isinstance(row, list) or len(row) < 2 or not isinstance(row[0], str):
            continue
        key = row[0]
        if key not in SETTING_DEFINITIONS:
            continue
        try:
            serialized = _serialize_value(key, row[1])
        except InvalidSettingsError:
            continue
        result[key] = serialized == "true" if SETTING_DEFINITIONS[key].kind == "boolean" else int(serialized)
    return result


def setting_catalog(defaults: dict[str, int | bool], overrides: dict[str, int | bool]) -> list[dict[str, Any]]:
    """Return administrator-facing setting definitions and effective values."""
    return [
        {
            "key": key,
            "kind": definition.kind,
            "minimum": definition.minimum,
            "maximum": definition.maximum,
            "label": definition.label,
            "description": definition.description,
            "default": defaults[key],
            "value": overrides.get(key, defaults[key]),
            "overridden": key in overrides,
        }
        for key, definition in SETTING_DEFINITIONS.items()
    ]


def _serialize_value(key: str, value: object) -> str:
    """Validate and serialize one setting value."""
    definition = SETTING_DEFINITIONS[key]
    if definition.kind == "boolean":
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str) and value.casefold() in {"true", "false"}:
            return value.casefold()
        raise InvalidSettingsError(f"{key} must be true or false")
    if isinstance(value, bool):
        raise InvalidSettingsError(f"{key} must be an integer")
    try:
        parsed = int(str(value).replace(",", "").replace("_", ""))
    except ValueError as error:
        raise InvalidSettingsError(f"{key} must be an integer") from error
    if definition.minimum is not None and parsed < definition.minimum:
        raise InvalidSettingsError(f"{key} must be at least {definition.minimum:,}")
    if definition.maximum is not None and parsed > definition.maximum:
        raise InvalidSettingsError(f"{key} must be at most {definition.maximum:,}")
    return str(parsed)
