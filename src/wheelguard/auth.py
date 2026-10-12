"""Authenticate access to protected Wheelguard repository routes."""

import base64
import binascii
import hashlib
import hmac
from collections.abc import Iterable
from datetime import datetime, timedelta

MINIMUM_TOKEN_LENGTH = 32
ADMIN_SESSION_TTL = timedelta(hours=8)


class AdminSessionAuthenticator:
    """Issue and verify short-lived sessions derived from the admin token."""

    def __init__(self, token: str | None, *, ttl: timedelta = ADMIN_SESSION_TTL) -> None:
        """Configure sessions that rotate automatically with the admin token."""
        self._key = token.encode() if token is not None else None
        self._ttl = ttl

    def issue(self, now: datetime) -> str:
        """Create a signed expiry value without placing the admin token in the cookie."""
        if self._key is None:
            raise ValueError("Administrator token sessions are disabled")
        expiry = str(int((now + self._ttl).timestamp()))
        signature = hmac.new(self._key, expiry.encode(), hashlib.sha256).hexdigest()
        return f"{expiry}.{signature}"

    def authorize(self, value: str | None, now: datetime) -> bool:
        """Validate a session expiry and signature in constant time."""
        if self._key is None or value is None:
            return False
        expiry, separator, signature = value.partition(".")
        if not separator or not expiry.isascii() or not expiry.isdigit():
            return False
        expected = hmac.new(self._key, expiry.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected) and int(expiry) >= int(now.timestamp())


class TokenAuthenticator:
    """Validate Basic-password or Bearer credentials against configured tokens."""

    def __init__(self, token: str | Iterable[str] | None) -> None:
        """Initialize optional token authentication."""
        tokens = (token,) if isinstance(token, str) else tuple(token or ())
        for configured_token in tokens:
            if len(configured_token) < MINIMUM_TOKEN_LENGTH:
                raise ValueError(f"Authentication tokens must contain at least {MINIMUM_TOKEN_LENGTH} characters")
        self._tokens = tuple(dict.fromkeys(tokens))

    @property
    def enabled(self) -> bool:
        """Report whether repository authentication is enabled."""
        return bool(self._tokens)

    def authorize(self, authorization: str | None) -> bool:
        """Validate an Authorization header without timing-sensitive equality."""
        if not self._tokens:
            return True
        candidate = authorization_token(authorization)
        return candidate is not None and self._matches(candidate)

    def _matches(self, candidate: str) -> bool:
        """Compare a candidate with every token so token order does not leak."""
        matched = False
        for token in self._tokens:
            matched |= hmac.compare_digest(candidate, token)
        return matched


def authorization_token(authorization: str | None) -> str | None:
    """Extract a Bearer token or Basic password from an authorization header."""
    if authorization is None:
        return None
    scheme, separator, credentials = authorization.partition(" ")
    if not separator:
        return None
    if scheme.casefold() == "bearer":
        return credentials
    if scheme.casefold() != "basic":
        return None
    try:
        decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    _, separator, password = decoded.partition(":")
    return password if separator else None


def configured_tokens(primary: object | None, additional: object | None) -> tuple[str, ...]:
    """Combine the legacy token and a comma-separated token list."""
    tokens = []
    if primary is not None and str(primary):
        tokens.append(str(primary))
    if additional is not None:
        tokens.extend(token.strip() for token in str(additional).split(",") if token.strip())
    return tuple(dict.fromkeys(tokens))
