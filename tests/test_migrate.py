import asyncio
from unittest.mock import AsyncMock, call

import pytest
from psycopg import sql

from wheelguard.migrate import _create_database_principal


@pytest.mark.parametrize(
    ("arity", "arguments"),
    [
        (3, "%s, %s, 'service'"),
        (4, "%s, %s, 'service', false"),
        (5, "%s, %s, 'service', false, false"),
    ],
)
def test_create_database_principal_uses_available_oid_function(arity: int, arguments: str) -> None:
    connection = AsyncMock()
    signature_result = AsyncMock()
    signature_result.fetchall.return_value = [("pgaadauth_create_principal_with_oid", "pgaadauth", arity)]
    connection.execute.side_effect = [signature_result, None]

    asyncio.run(_create_database_principal(connection, "wheelguard-app", "00000000-0000-0000-0000-000000000001"))

    assert connection.execute.await_args_list == [
        call(
            "SELECT p.proname, n.nspname, p.pronargs FROM pg_proc AS p "
            "JOIN pg_namespace AS n ON n.oid = p.pronamespace "
            "WHERE p.proname IN ('pgaadauth_create_principal_with_oid', 'pgaadauth_create_principal') "
            "AND p.prokind = 'f' ORDER BY p.proname DESC, n.nspname"
        ),
        call(
            sql.SQL("SELECT * FROM {}.{}(" + arguments + ")").format(
                sql.Identifier("pgaadauth"), sql.Identifier("pgaadauth_create_principal_with_oid")
            ),
            ("wheelguard-app", "00000000-0000-0000-0000-000000000001"),
        ),
    ]


def test_create_database_principal_falls_back_to_graph_lookup() -> None:
    connection = AsyncMock()
    signature_result = AsyncMock()
    signature_result.fetchall.return_value = [("pgaadauth_create_principal", "pgaadauth", 3)]
    connection.execute.side_effect = [signature_result, None]

    asyncio.run(_create_database_principal(connection, "wheelguard-app", "00000000-0000-0000-0000-000000000001"))

    assert connection.execute.await_args_list[1] == call(
        sql.SQL("SELECT * FROM {}.{}(%s, false, false)").format(
            sql.Identifier("pgaadauth"), sql.Identifier("pgaadauth_create_principal")
        ),
        ("wheelguard-app",),
    )


def test_create_database_principal_requires_supported_function() -> None:
    connection = AsyncMock()
    signature_result = AsyncMock()
    signature_result.fetchall.return_value = []
    connection.execute.return_value = signature_result

    with pytest.raises(RuntimeError, match="does not provide a supported"):
        asyncio.run(_create_database_principal(connection, "wheelguard-app", "00000000-0000-0000-0000-000000000001"))
