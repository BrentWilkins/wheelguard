"""Authenticate access to protected Wheelguard repository routes."""

import base64
import binascii
import hmac
from collections.abc import Iterable

MINIMUM_TOKEN_LENGTH = 32


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
        if authorization is None:
            return False

        scheme, separator, credentials = authorization.partition(" ")
        if not separator:
            return False
        if scheme.casefold() == "bearer":
            return self._matches(credentials)
        if scheme.casefold() != "basic":
            return False

        try:
            decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        _, separator, password = decoded.partition(":")
        return bool(separator) and self._matches(password)

    def _matches(self, candidate: str) -> bool:
        """Compare a candidate with every token so token order does not leak."""
        matched = False
        for token in self._tokens:
            matched |= hmac.compare_digest(candidate, token)
        return matched


def configured_tokens(primary: object | None, additional: object | None) -> tuple[str, ...]:
    """Combine the legacy token and a comma-separated token list."""
    tokens = []
    if primary is not None and str(primary):
        tokens.append(str(primary))
    if additional is not None:
        tokens.extend(token.strip() for token in str(additional).split(",") if token.strip())
    return tuple(dict.fromkeys(tokens))
