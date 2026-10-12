"""Validate platform identities without distributing long-lived user secrets."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class IdentityError(ValueError):
    """Report an invalid or unauthorized platform identity."""


def entra_actor(encoded_principal: str | None) -> str:
    """Return the named user from an Azure Container Apps principal header."""
    if not encoded_principal:
        raise IdentityError("Microsoft Entra authentication required")
    try:
        padded = encoded_principal + "=" * (-len(encoded_principal) % 4)
        principal = json.loads(base64.b64decode(padded, validate=True))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise IdentityError("Invalid Microsoft Entra principal") from error
    if not isinstance(principal, dict):
        raise IdentityError("Invalid Microsoft Entra principal")
    claims = principal.get("claims")
    if not isinstance(claims, list):
        raise IdentityError("Invalid Microsoft Entra principal")
    preferred = {
        "preferred_username",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    }
    for claim in claims:
        if isinstance(claim, dict) and claim.get("typ") in preferred and isinstance(claim.get("val"), str):
            value = claim["val"].strip()
            if value:
                return str(value)
    raise IdentityError("Microsoft Entra principal has no usable identity")


@dataclass(frozen=True, slots=True)
class PublisherIdentity:
    """Describe an authorized GitLab publishing job."""

    project_path: str
    subject: str
    pipeline_id: str | None


class GitLabOidcValidator:
    """Validate short-lived GitLab CI ID tokens against a strict allowlist."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        allowed_projects: tuple[str, ...],
        *,
        client: httpx.AsyncClient | None = None,
        cache_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        """Configure issuer discovery and authorized project paths."""
        if not issuer.startswith("https://") or not allowed_projects:
            raise ValueError("GitLab OIDC requires an HTTPS issuer and at least one allowed project")
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._allowed_projects = frozenset(allowed_projects)
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None
        self._cache_ttl = cache_ttl
        self._jwks: dict[str, Any] | None = None
        self._jwks_expires = datetime.min.replace(tzinfo=UTC)

    async def validate(self, token: str) -> PublisherIdentity:
        """Verify signature and claims, requiring an approved protected ref."""
        import jwt

        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not isinstance(kid, str):
                raise IdentityError("Publisher token has no key identifier")
            jwks = await self._keys()
            key_data = next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)
            if not isinstance(key_data, dict):
                jwks = await self._keys(force=True)
                key_data = next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)
            if not isinstance(key_data, dict):
                raise IdentityError("Publisher signing key is unknown")
            key = jwt.PyJWK.from_dict(key_data).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except IdentityError:
            raise
        except (jwt.PyJWTError, ValueError, KeyError) as error:
            raise IdentityError("Invalid publisher identity token") from error
        project = claims.get("project_path")
        protected = claims.get("ref_protected")
        if not isinstance(project, str) or (
            "*" not in self._allowed_projects and project not in self._allowed_projects
        ):
            raise IdentityError("Publisher project is not authorized")
        if protected not in {True, "true"}:
            raise IdentityError("Publishing requires a protected GitLab ref")
        return PublisherIdentity(str(project), str(claims["sub"]), _optional_string(claims.get("pipeline_id")))

    async def _keys(self, *, force: bool = False) -> dict[str, Any]:
        now = datetime.now(UTC)
        if not force and self._jwks is not None and now < self._jwks_expires:
            return self._jwks
        discovery = await self._client.get(f"{self._issuer}/.well-known/openid-configuration")
        discovery.raise_for_status()
        document = discovery.json()
        uri = document.get("jwks_uri") if isinstance(document, dict) else None
        if not isinstance(uri, str) or not uri.startswith(f"{self._issuer}/"):
            raise IdentityError("GitLab OIDC discovery returned an unsafe key URL")
        response = await self._client.get(uri)
        response.raise_for_status()
        keys = response.json()
        if not isinstance(keys, dict) or not isinstance(keys.get("keys"), list):
            raise IdentityError("GitLab OIDC key response is invalid")
        self._jwks = keys
        self._jwks_expires = now + self._cache_ttl
        return keys

    async def aclose(self) -> None:
        """Close the owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()


def authorization_token(header: str | None) -> str:
    """Extract a bearer token or the password portion of Basic authentication."""
    if not header:
        raise IdentityError("Publisher authentication required")
    scheme, separator, value = header.partition(" ")
    if not separator:
        raise IdentityError("Publisher authentication required")
    if scheme.casefold() == "bearer" and value:
        return value
    if scheme.casefold() == "basic":
        try:
            decoded = base64.b64decode(value, validate=True).decode()
        except (ValueError, UnicodeDecodeError) as error:
            raise IdentityError("Invalid publisher authorization") from error
        _, separator, password = decoded.partition(":")
        if separator and password:
            return password
    raise IdentityError("Publisher authentication required")


def _optional_string(value: object) -> str | None:
    return str(value) if value is not None else None
