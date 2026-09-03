import base64

from wheelguard.auth import TokenAuthenticator

TOKEN = "correct-horse-battery-staple-token"


def test_authentication_is_optional() -> None:
    authenticator = TokenAuthenticator(None)

    assert authenticator.enabled is False
    assert authenticator.authorize(None)


def test_accepts_bearer_and_basic_password_tokens() -> None:
    authenticator = TokenAuthenticator(TOKEN)
    basic = base64.b64encode(f"wheelguard:{TOKEN}".encode()).decode()

    assert authenticator.enabled is True
    assert authenticator.authorize(f"Bearer {TOKEN}")
    assert authenticator.authorize(f"Basic {basic}")


def test_accepts_any_configured_token() -> None:
    replacement = "replacement-horse-battery-staple-token"
    authenticator = TokenAuthenticator((TOKEN, replacement))

    assert authenticator.authorize(f"Bearer {TOKEN}")
    assert authenticator.authorize(f"Bearer {replacement}")
    assert not authenticator.authorize("Bearer unconfigured-horse-battery-staple-token")


def test_rejects_missing_malformed_and_incorrect_credentials() -> None:
    authenticator = TokenAuthenticator(TOKEN)
    incorrect = base64.b64encode(b"wheelguard:wrong").decode()

    assert not authenticator.authorize(None)
    assert not authenticator.authorize("Basic not-base64")
    assert not authenticator.authorize(f"Basic {incorrect}")
    assert not authenticator.authorize("Digest anything")


def test_rejects_empty_and_short_tokens() -> None:
    """Reject configured credentials that could enable empty-password access."""
    for token in ("", "too-short"):
        try:
            TokenAuthenticator(token)
        except ValueError:
            pass
        else:
            raise AssertionError("weak token was accepted")
