from datetime import timedelta

from wheelguard.config import Settings


def test_default_artifact_limit_matches_pypi() -> None:
    assert Settings().maximum_artifact_bytes == 100 * 1024 * 1024


def test_default_advisory_refresh_window() -> None:
    settings = Settings()

    assert settings.advisory_refresh_interval == timedelta(hours=1)
    assert settings.advisory_active_window == timedelta(days=30)
