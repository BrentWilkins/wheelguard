"""Test bounded PostgreSQL connection reuse without a live database."""

import asyncio
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from psycopg.pq import TransactionStatus

from wheelguard.postgres import PostgresDatabase


class Credential:
    def __init__(self) -> None:
        self.requests = 0

    async def get_token(self, scope: str) -> SimpleNamespace:
        assert scope == "scope"
        self.requests += 1
        return SimpleNamespace(token="secret")


class Connection:
    def __init__(self) -> None:
        self.closed = False
        self.broken = False
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.rollbacks = 0
        self.executions: list[tuple[str, tuple[Any, ...] | None]] = []
        self.commits = 0

    async def execute(self, query: str, values: tuple[Any, ...] | None = None) -> None:
        self.executions.append((query, values))

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1
        self.info.transaction_status = TransactionStatus.IDLE

    async def close(self) -> None:
        self.closed = True


def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_postgres_connections_are_reused_and_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = Credential()
    connections: list[Connection] = []

    async def connect(*args: Any, **kwargs: Any) -> Connection:
        assert args == ("postgresql://example",)
        assert kwargs["password"] == "secret"
        connections.append(Connection())
        return connections[-1]

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", staticmethod(connect))
    database = PostgresDatabase("postgresql://example", credential, "scope", maximum_connections=2)  # type: ignore[arg-type]

    async with database._connection() as first:
        first.info.transaction_status = TransactionStatus.INTRANS
    async with database._connection() as second:
        assert second is first

    assert credential.requests == 1
    assert len(connections) == 1
    assert connections[0].rollbacks == 1
    await database.aclose()
    assert connections[0].closed


@pytest.mark.anyio
async def test_postgres_connection_creation_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = Credential()
    connections: list[Connection] = []
    active = 0
    maximum_active = 0

    async def connect(*args: Any, **kwargs: Any) -> Connection:
        connections.append(Connection())
        return connections[-1]

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", staticmethod(connect))
    database = PostgresDatabase("postgresql://example", credential, "scope", maximum_connections=2)  # type: ignore[arg-type]

    async def use_connection() -> None:
        nonlocal active, maximum_active
        async with database._connection():
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1

    await asyncio.gather(*(use_connection() for _ in range(6)))

    assert len(connections) == credential.requests == maximum_active == 2
    await database.aclose()
    assert all(connection.closed for connection in connections)


@pytest.mark.anyio
async def test_artifact_registration_uses_one_batched_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = Credential()
    connection = Connection()

    async def connect(*args: Any, **kwargs: Any) -> Connection:
        return connection

    monkeypatch.setattr(psycopg.AsyncConnection, "connect", staticmethod(connect))
    database = PostgresDatabase("postgresql://example", credential, "scope")  # type: ignore[arg-type]
    files = [
        {
            "filename": f"demo-1.0-{index}-py3-none-any.whl",
            "url": f"https://files.example/{index}.whl",
            "hashes": {"sha256": f"{index:064x}"},
        }
        for index in range(3)
    ]

    await database.register_artifacts("demo", {"files": files})

    assert len(connection.executions) == 1
    assert "jsonb_to_recordset" in connection.executions[0][0]
    assert connection.commits == 1
