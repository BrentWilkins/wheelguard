from datetime import UTC, datetime

import pytest

from wheelguard.repository_tokens import RepositoryTokenRecord, issue_repository_token, repository_token_digest
from wheelguard.token_cli import _execute


def test_issued_tokens_are_unique_and_only_their_digests_need_storage() -> None:
    first = issue_repository_token()
    second = issue_repository_token()

    assert first.startswith("wg_")
    assert len(first) >= 32
    assert first != second
    assert repository_token_digest(first) != repository_token_digest(second)
    assert first.encode() not in repository_token_digest(first)


class FakeTokenDatabase:
    def __init__(self) -> None:
        self.created: tuple[str, str] | None = None
        self.revoked: tuple[str, str] | None = None

    async def create_repository_token(self, name: str, *, actor: str) -> str:
        self.created = (name, actor)
        return "wg_" + "s" * 43

    async def list_repository_tokens(self) -> list[RepositoryTokenRecord]:
        return [
            RepositoryTokenRecord(
                name="brent",
                created_at=datetime(2026, 9, 18, tzinfo=UTC),
                created_by="admin@example.com",
                last_used_at=None,
                revoked_at=None,
                revoked_by=None,
            )
        ]

    async def revoke_repository_token(self, name: str, *, actor: str) -> bool:
        self.revoked = (name, actor)
        return True


@pytest.mark.anyio
async def test_token_cli_create_displays_plaintext_once(capsys: pytest.CaptureFixture[str]) -> None:
    database = FakeTokenDatabase()
    arguments = type("Arguments", (), {"command": "create", "name": "brent", "actor": "admin", "json": False})()

    assert await _execute(arguments, database) == 0

    output = capsys.readouterr().out
    assert "wg_" in output
    assert "cannot display it again" in output
    assert database.created == ("brent", "admin")


@pytest.mark.anyio
async def test_token_cli_lists_metadata_without_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    database = FakeTokenDatabase()
    arguments = type("Arguments", (), {"command": "list", "actor": "admin", "json": True})()

    assert await _execute(arguments, database) == 0

    output = capsys.readouterr().out
    assert '"name": "brent"' in output
    assert '"token"' not in output
