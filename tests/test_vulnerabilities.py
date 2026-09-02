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
    )

    assert marked["files"][0]["yanked"] == "Wheelguard advisories: GHSA-test"
    assert allows == {"2.0": "allow"}


def test_fresh_release_is_not_needed_when_an_aged_safe_release_exists() -> None:
    payload = _payload()
    payload["files"].insert(1, {"filename": "demo-1.1.tar.gz", "upload-time": "2026-01-02T00:00:00Z"})

    allows = automatic_fixed_version_allows(
        payload,
        {"1.0": ["GHSA-test"], "1.1": [], "2.0": []},
        now=datetime(2026, 9, 1, tzinfo=UTC),
        minimum_age=timedelta(days=14),
    )

    assert allows == {}


def test_osv_result_count_must_match_queries() -> None:
    with pytest.raises(InvalidOsvResponseError, match="result count"):
        parse_osv_results({"results": []}, ["1.0"])
