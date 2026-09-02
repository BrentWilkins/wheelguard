"""Test the combined publication-age and administrator override policy."""

from datetime import UTC, datetime, timedelta

from wheelguard.policy import ReleasePolicy


def _payload() -> dict[str, object]:
    return {
        "meta": {"api-version": "1.4"},
        "name": "demo",
        "versions": ["1.0", "2.0", "3.0"],
        "files": [
            {"filename": "demo-1.0.tar.gz", "upload-time": "2026-01-01T00:00:00Z"},
            {"filename": "demo-2.0.tar.gz", "upload-time": "2026-08-31T00:00:00Z"},
            {"filename": "demo-3.0.tar.gz", "upload-time": "2026-01-01T00:00:00Z"},
        ],
    }


def test_explicit_allow_bypasses_minimum_age() -> None:
    result = ReleasePolicy(timedelta(days=14)).apply(
        _payload(),
        now=datetime(2026, 9, 1, tzinfo=UTC),
        overrides={"2.0": "allow"},
    )

    assert [file["filename"] for file in result.payload["files"]] == [
        "demo-1.0.tar.gz",
        "demo-2.0.tar.gz",
        "demo-3.0.tar.gz",
    ]


def test_explicit_block_wins_over_minimum_age() -> None:
    result = ReleasePolicy(timedelta(days=14)).apply(
        _payload(),
        now=datetime(2026, 9, 1, tzinfo=UTC),
        overrides={"3.0": "block"},
    )

    assert [file["filename"] for file in result.payload["files"]] == ["demo-1.0.tar.gz"]
    assert result.payload["versions"] == ["1.0"]
    assert result.hidden_files == 2
