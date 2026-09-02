from datetime import UTC, datetime, timedelta

import pytest

from wheelguard.policy import MinimumAgePolicy

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def test_hides_new_files_and_versions() -> None:
    payload = {
        "versions": ["1.0", "2.0"],
        "files": [
            {"filename": "demo-1.0.tar.gz", "upload-time": "2026-08-01T00:00:00Z"},
            {"filename": "demo-2.0.tar.gz", "upload-time": "2026-08-25T00:00:00Z"},
        ],
    }
    result = MinimumAgePolicy(timedelta(days=14)).apply(payload, now=NOW)
    assert [file["filename"] for file in result.payload["files"]] == ["demo-1.0.tar.gz"]
    assert result.payload["versions"] == ["1.0"]
    assert result.hidden_files == 1


def test_cutoff_is_inclusive() -> None:
    payload = {"files": [{"filename": "demo-1.0.tar.gz", "upload-time": "2026-08-18T00:00:00Z"}]}
    assert MinimumAgePolicy(timedelta(days=14)).apply(payload, now=NOW).visible_files == 1


def test_missing_time_can_fail_closed() -> None:
    result = MinimumAgePolicy(timedelta(days=14)).apply({"files": [{"filename": "demo-1.0.tar.gz"}]}, now=NOW)
    assert result.hidden_files == 1


def test_missing_time_can_be_allowed_explicitly() -> None:
    result = MinimumAgePolicy(timedelta(days=14), allow_missing_upload_time=True).apply(
        {"files": [{"filename": "demo-1.0.tar.gz"}]}, now=NOW
    )
    assert result.visible_files == 1


def test_clock_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="timezone"):
        MinimumAgePolicy(timedelta(days=14)).apply({"files": []}, now=datetime(2026, 9, 1))
