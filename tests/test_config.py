from datetime import timedelta

import pytest

from wheelguard.config import Settings


def test_default_artifact_limit_matches_pypi() -> None:
    assert Settings().maximum_artifact_bytes == 100 * 1024 * 1024


def test_default_advisory_refresh_window() -> None:
    settings = Settings()

    assert settings.advisory_refresh_interval == timedelta(hours=1)
    assert settings.advisory_active_window == timedelta(days=30)


def test_missing_upload_timestamps_fail_closed_by_default() -> None:
    """Require an explicit compatibility opt-out from timestamp enforcement."""

    assert Settings().allow_missing_upload_time is False


def test_loads_additional_authentication_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHEELGUARD_AUTH_TOKENS", f"{'a' * 32}, {'b' * 32}")

    assert Settings.from_environment().auth_tokens == ("a" * 32, "b" * 32)


def test_rejects_insecure_upstream_and_empty_artifact_allowlist() -> None:
    """Keep self-hosted network destinations explicit and encrypted."""
    with pytest.raises(ValueError, match="HTTPS URL"):
        Settings(upstream_url="http://pypi.example/simple/")
    with pytest.raises(ValueError, match="cannot be empty"):
        Settings(allowed_artifact_hosts=frozenset())
