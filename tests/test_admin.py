from datetime import UTC, datetime, timedelta

import pytest

from wheelguard.admin import InvalidOverrideError, admin_content_security_policy, parse_override_request


def test_admin_content_security_policy_allows_same_origin_api() -> None:
    policy = admin_content_security_policy("test-nonce")

    assert "script-src 'nonce-test-nonce'" in policy
    assert "connect-src 'self'" in policy
    assert "form-action 'self'" in policy
    assert "frame-ancestors 'none'" in policy


def test_parse_override_request_normalizes_release() -> None:
    expiry = (datetime.now(UTC) + timedelta(days=1)).isoformat()

    result = parse_override_request(
        {
            "project": "Example_Package",
            "version": "1.0.0",
            "action": "allow",
            "reason": "Fixed release is still inside the cooldown",
            "expires_at": expiry,
        }
    )

    assert result.project == "example-package"
    assert result.version == "1.0.0"
    assert result.action == "allow"
    assert result.expires_at is not None and result.expires_at.endswith("Z")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("project", ""),
        ("project", "not a valid name!"),
        ("project", "a" * 201),
        ("version", "not a version !"),
        ("version", "1" * 201),
        ("action", "permit"),
        ("reason", ""),
        ("reason", "a" * 501),
        ("expires_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_parse_override_request_rejects_invalid_fields(field: str, value: str) -> None:
    request = {
        "project": "demo",
        "version": "1.0",
        "action": "block",
        "reason": "Known vulnerability",
        "expires_at": None,
    }
    request[field] = value

    with pytest.raises(InvalidOverrideError):
        parse_override_request(request)
