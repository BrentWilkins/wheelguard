import base64

from wheelguard.auth import TokenAuthenticator


def test_authentication_is_optional() -> None:
    authenticator = TokenAuthenticator(None)

    assert authenticator.enabled is False
    assert authenticator.authorize(None)


def test_accepts_bearer_and_basic_password_tokens() -> None:
    authenticator = TokenAuthenticator("correct-horse")
    basic = base64.b64encode(b"wheelguard:correct-horse").decode()

    assert authenticator.enabled is True
    assert authenticator.authorize("Bearer correct-horse")
    assert authenticator.authorize(f"Basic {basic}")


def test_rejects_missing_malformed_and_incorrect_credentials() -> None:
    authenticator = TokenAuthenticator("correct-horse")
    incorrect = base64.b64encode(b"wheelguard:wrong").decode()

    assert not authenticator.authorize(None)
    assert not authenticator.authorize("Basic not-base64")
    assert not authenticator.authorize(f"Basic {incorrect}")
    assert not authenticator.authorize("Digest anything")
