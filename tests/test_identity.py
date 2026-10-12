"""Test Azure administrator and GitLab publisher identities."""

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from wheelguard.identity import GitLabOidcValidator, IdentityError, authorization_token, entra_actor


def principal(*claims: tuple[str, str]) -> str:
    """Encode an Easy Auth principal header."""
    body = json.dumps({"claims": [{"typ": key, "val": value} for key, value in claims]}).encode()
    return base64.b64encode(body).decode()


def test_entra_actor_uses_verified_named_claim() -> None:
    assert entra_actor(principal(("preferred_username", "admin@example.com"))) == "admin@example.com"


@pytest.mark.parametrize("header", [None, "", "not-base64", base64.b64encode(b"{}").decode()])
def test_entra_actor_rejects_missing_or_invalid_principal(header: str | None) -> None:
    with pytest.raises(IdentityError):
        entra_actor(header)


def test_authorization_token_accepts_uv_basic_password() -> None:
    encoded = base64.b64encode(b"__token__:signed-job-token").decode()
    assert authorization_token(f"Basic {encoded}") == "signed-job-token"
    assert authorization_token("Bearer signed-job-token") == "signed-job-token"


def test_gitlab_oidc_requires_allowed_project_and_protected_ref() -> None:
    """Accept only short-lived publishing identities from the configured project."""
    issuer = "https://gitlab.example.test"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = "test-key"

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"jwks_uri": f"{issuer}/oauth/discovery/keys"})
        return httpx.Response(200, json={"keys": [jwk]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    validator = GitLabOidcValidator(issuer, "wheelguard-publisher", ("group/package",), client=client)
    now = datetime.now(UTC)

    def token(project: str, protected: bool) -> str:
        return jwt.encode(
            {
                "iss": issuer,
                "aud": "wheelguard-publisher",
                "sub": "project_path:group/package:ref_type:branch:ref:main",
                "iat": now,
                "exp": now + timedelta(minutes=5),
                "project_path": project,
                "ref_protected": protected,
                "pipeline_id": "42",
            },
            private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    async def exercise() -> None:
        identity = await validator.validate(token("group/package", True))
        assert identity.project_path == "group/package"
        assert identity.pipeline_id == "42"
        with pytest.raises(IdentityError, match="not authorized"):
            await validator.validate(token("other/package", True))
        with pytest.raises(IdentityError, match="protected"):
            await validator.validate(token("group/package", False))
        await client.aclose()

    asyncio.run(exercise())
