"""Test pure OSV response and safe-fallback behavior."""

from datetime import UTC, datetime, timedelta

import pytest

from wheelguard.vulnerabilities import (
    InvalidOsvResponseError,
    apply_advisories,
    automatic_fixed_version_allows,
    parse_osv_results,
)


def _payload() -> dict[str, object]:
    return {
        "files": [
            {"filename": "demo-1.0.tar.gz", "upload-time": "2026-01-01T00:00:00Z"},
            {"filename": "demo-2.0.tar.gz", "upload-time": "2026-08-31T00:00:00Z"},
        ]
    }


def test_known_vulnerability_is_yanked_and_fresh_fix_is_allowed() -> None:
    advisories = {"1.0": ["GHSA-test"], "2.0": []}

    marked = apply_advisories(_payload(), advisories)
    allows = automatic_fixed_version_allows(
        marked,
        advisories,
        now=datetime(2026, 9, 1, tzinfo=UTC),
        minimum_age=timedelta(days=14),
        fallback_minimum_age=timedelta(hours=24),
    )

    assert marked["files"][0]["yanked"] == "Wheelguard advisories: GHSA-test"
    assert allows == {"2.0": "fallback"}


def test_fresh_release_is_not_needed_when_an_aged_safe_release_exists() -> None:
    payload = _payload()
    payload["files"].insert(1, {"filename": "demo-1.1.tar.gz", "upload-time": "2026-01-02T00:00:00Z"})

    allows = automatic_fixed_version_allows(
        payload,
        {"1.0": ["GHSA-test"], "1.1": [], "2.0": []},
        now=datetime(2026, 9, 1, tzinfo=UTC),
        minimum_age=timedelta(days=14),
        fallback_minimum_age=timedelta(hours=24),
    )

    assert allows == {}


def test_fixed_release_younger_than_fallback_floor_is_not_allowed() -> None:
    """Do not trade a known vulnerability for an unseasoned release immediately."""
    payload = _payload()
    payload["files"][1]["upload-time"] = "2026-08-31T12:00:00Z"  # type: ignore[index]
    allows = automatic_fixed_version_allows(
        payload,
        {"1.0": ["GHSA-test"], "2.0": []},
        now=datetime(2026, 9, 1, tzinfo=UTC),
        minimum_age=timedelta(days=14),
        fallback_minimum_age=timedelta(hours=24),
    )
    assert allows == {}


def test_osv_result_count_must_match_queries() -> None:
    with pytest.raises(InvalidOsvResponseError, match="result count"):
        parse_osv_results({"results": []}, ["1.0"])


def test_fallback_checks_each_file_age() -> None:
    """An older source archive must not admit a newly uploaded wheel."""
    from wheelguard.policy import ReleasePolicy

    payload = _payload()
    payload["files"].append({"filename": "demo-2.0-py3-none-any.whl", "upload-time": "2026-08-31T23:59:00Z"})
    now = datetime(2026, 9, 1, tzinfo=UTC)
    fallback = automatic_fixed_version_allows(
        payload,
        {"1.0": ["GHSA-test"], "2.0": []},
        now=now,
        minimum_age=timedelta(days=14),
        fallback_minimum_age=timedelta(hours=24),
    )
    result = ReleasePolicy(timedelta(days=14)).apply(
        payload,
        now=now,
        overrides=fallback,
        fallback_minimum_age=timedelta(hours=24),
    )
    assert [file["filename"] for file in result.payload["files"]] == ["demo-1.0.tar.gz", "demo-2.0.tar.gz"]
