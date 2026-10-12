"""Apply forward-only PostgreSQL schema migrations under an advisory lock."""

from __future__ import annotations

import asyncio
from importlib.resources import files
from typing import cast

import psycopg
from azure.identity.aio import DefaultAzureCredential
from psycopg import sql

from wheelguard.config import Settings

LOCK_ID = 878_255_274_176_401


async def _create_database_principal(
    connection: psycopg.AsyncConnection[tuple[object, ...]], principal_name: str, object_id: str
) -> None:
    """Create an Entra principal using the best API available on the server."""
    result = await connection.execute(
        "SELECT p.proname, n.nspname, p.pronargs FROM pg_proc AS p "
        "JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "WHERE p.proname IN ('pgaadauth_create_principal_with_oid', 'pgaadauth_create_principal') "
        "AND p.prokind = 'f' ORDER BY p.proname DESC, n.nspname"
    )
    signatures = [(cast(str, row[0]), cast(str, row[1]), cast(int, row[2])) for row in await result.fetchall()]
    oid_function = next(
        (
            (schema, arity)
            for function, schema, arity in signatures
            if function == "pgaadauth_create_principal_with_oid" and arity in {5, 4, 3}
        ),
        None,
    )
    if oid_function is not None:
        schema, arity = oid_function
        arguments = {
            5: "%s, %s, 'service', false, false",
            4: "%s, %s, 'service', false",
            3: "%s, %s, 'service'",
        }[arity]
        statement = sql.SQL("SELECT * FROM {}.{}(" + arguments + ")").format(
            sql.Identifier(schema), sql.Identifier("pgaadauth_create_principal_with_oid")
        )
        await connection.execute(statement, (principal_name, object_id))
        return

    graph_function = next(
        (schema for function, schema, arity in signatures if function == "pgaadauth_create_principal" and arity == 3),
        None,
    )
    if graph_function is None:
        raise RuntimeError("PostgreSQL does not provide a supported pgaadauth principal creation function")
    statement = sql.SQL("SELECT * FROM {}.{}(%s, false, false)").format(
        sql.Identifier(graph_function), sql.Identifier("pgaadauth_create_principal")
    )
    await connection.execute(statement, (principal_name,))


async def migrate() -> None:
    """Apply every packaged migration exactly once."""
    settings = Settings.from_environment()
    if settings.database_url is None:
        raise SystemExit("WHEELGUARD_DATABASE_URL is required")
    credential = DefaultAzureCredential()
    try:
        token = await credential.get_token(settings.database_token_scope)
        async with await psycopg.AsyncConnection.connect(settings.database_url, password=token.token) as connection:
            await connection.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
            try:
                await connection.execute(
                    "CREATE TABLE IF NOT EXISTS wheelguard_schema_migrations "
                    "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
                migration_root = files("wheelguard").joinpath("postgres_migrations")
                for migration in sorted(migration_root.iterdir(), key=lambda item: item.name):
                    if not migration.name.endswith(".sql"):
                        continue
                    existing = await connection.execute(
                        "SELECT 1 FROM wheelguard_schema_migrations WHERE version = %s", (migration.name,)
                    )
                    if await existing.fetchone() is not None:
                        continue
                    await connection.execute(migration.read_text(), prepare=False)
                    await connection.execute(
                        "INSERT INTO wheelguard_schema_migrations (version) VALUES (%s)", (migration.name,)
                    )
                    await connection.commit()
                if settings.database_app_principal and settings.database_app_object_id:
                    try:
                        await _create_database_principal(
                            connection, settings.database_app_principal, settings.database_app_object_id
                        )
                    except psycopg.errors.RaiseException as error:
                        if "already exists" not in str(error):
                            raise
                        await connection.rollback()
                    principal = sql.Identifier(settings.database_app_principal)
                    await connection.execute(
                        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                            sql.Identifier(connection.info.dbname), principal
                        )
                    )
                    await connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(principal))
                    await connection.execute(
                        sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(
                            principal
                        )
                    )
                    await connection.execute(
                        sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(principal)
                    )
                    await connection.commit()
            finally:
                # Clear an aborted statement transaction before releasing the
                # session lock; closing the connection remains the final fallback.
                await connection.rollback()
                await connection.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
    finally:
        await credential.close()


def main() -> None:
    """Run migrations from a Container Apps Job or operator shell."""
    asyncio.run(migrate())


if __name__ == "__main__":
    main()
