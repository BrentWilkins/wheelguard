"""Test administrator-editable runtime setting validation."""

import pytest

from wheelguard.runtime_settings import (
    InvalidSettingsError,
    decode_stored_settings,
    parse_settings_update,
    setting_catalog,
)


def test_partial_update_accepts_grouped_integers_and_boolean() -> None:
    assert parse_settings_update(
        {"minimum_age_days": 7, "maximum_artifact_bytes": "104,857,600", "osv_enabled": False}
    ) == {
        "minimum_age_days": "7",
        "maximum_artifact_bytes": "104857600",
        "osv_enabled": "false",
    }


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({}, "At least one"),
        ({"unknown": 1}, "Unknown setting"),
        ({"minimum_age_days": -1}, "at least 0"),
        ({"osv_enabled": "yes"}, "true or false"),
    ],
)
def test_invalid_updates_are_rejected(raw: object, message: str) -> None:
    with pytest.raises(InvalidSettingsError, match=message):
        parse_settings_update(raw)


def test_corrupt_or_unknown_database_values_are_ignored() -> None:
    decoded = decode_stored_settings(
        [["minimum_age_days", "21"], ["osv_enabled", "true"], ["metadata_ttl_seconds", "bad"], ["other", "1"]]
    )

    assert decoded == {"minimum_age_days": 21, "osv_enabled": True}


def test_catalog_distinguishes_defaults_from_overrides() -> None:
    defaults = {
        "minimum_age_days": 14,
        "metadata_ttl_seconds": 300,
        "maximum_artifact_bytes": 104_857_600,
        "osv_enabled": True,
        "advisory_ttl_seconds": 3_600,
        "advisory_active_days": 30,
    }

    catalog = setting_catalog(defaults, {"minimum_age_days": 21})

    assert catalog[0]["value"] == 21
    assert catalog[0]["overridden"] is True
    assert catalog[1]["overridden"] is False
