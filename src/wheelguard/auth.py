"""Authenticate access to protected Wheelguard repository routes."""

import base64
import binascii
import hmac


class TokenAuthenticator:
    """Validate Basic-password or Bearer credentials against one token."""

    def __init__(self, token: str | None) -> None:
        """Initialize optional token authentication."""
        self._token = token

    @property
    def enabled(self) -> bool:
        """Report whether repository authentication is enabled."""
        return self._token is not None

    def authorize(self, authorization: str | None) -> bool:
        """Validate an Authorization header without timing-sensitive equality."""
        if self._token is None:
            return True
        if authorization is None:
            return False

        scheme, separator, credentials = authorization.partition(" ")
        if not separator:
            return False
        if scheme.casefold() == "bearer":
            return hmac.compare_digest(credentials, self._token)
        if scheme.casefold() != "basic":
            return False

        try:
            decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        _, separator, password = decoded.partition(":")
        return bool(separator) and hmac.compare_digest(password, self._token)
