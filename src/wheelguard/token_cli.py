"""Manage individually revocable repository credentials."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from typing import Any

from azure.identity.aio import DefaultAzureCredential
from psycopg.errors import UniqueViolation

from wheelguard.config import Settings
from wheelguard.postgres import PostgresDatabase


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wheelguard token", description="Manage repository access tokens")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create a named token")
    create.add_argument("name")
    create.add_argument("--actor", default=getpass.getuser(), help="administrator identity recorded in the audit log")
    create.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    list_tokens = commands.add_parser("list", help="list token metadata")
    list_tokens.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    revoke = commands.add_parser("revoke", help="revoke an active token")
    revoke.add_argument("name")
    revoke.add_argument("--actor", default=getpass.getuser(), help="administrator identity recorded in the audit log")
    revoke.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot encode {type(value).__name__}")


async def _execute(arguments: argparse.Namespace, database: Any) -> int:
    if arguments.command == "create":
        try:
            token = await database.create_repository_token(arguments.name, actor=arguments.actor)
        except UniqueViolation:
            print(f"A repository token named {arguments.name!r} already exists")
            return 1
        result = {"name": arguments.name, "token": token}
        if arguments.json:
            print(json.dumps(result))
        else:
            print(f"Name: {arguments.name}\nToken: {token}\n\nSave this token now; Wheelguard cannot display it again.")
        return 0
    if arguments.command == "list":
        records = await database.list_repository_tokens()
        if arguments.json:
            print(json.dumps([asdict(record) for record in records], default=_json_default))
        else:
            print("NAME\tSTATE\tCREATED BY\tCREATED AT\tLAST USED")
            for record in records:
                state = "revoked" if record.revoked_at is not None else "active"
                last_used = record.last_used_at.isoformat() if record.last_used_at is not None else "never"
                print(f"{record.name}\t{state}\t{record.created_by}\t{record.created_at.isoformat()}\t{last_used}")
        return 0
    revoked = await database.revoke_repository_token(arguments.name, actor=arguments.actor)
    if not revoked:
        print(f"No active repository token named {arguments.name!r}")
        return 1
    if arguments.json:
        print(json.dumps({"name": arguments.name, "revoked": True}))
    else:
        print(f"Revoked repository token {arguments.name!r}")
    return 0


async def _run(arguments: argparse.Namespace) -> int:
    settings = Settings.from_environment()
    if settings.database_url is None:
        raise SystemExit("WHEELGUARD_DATABASE_URL is required")
    credential = DefaultAzureCredential()
    try:
        database = PostgresDatabase(settings.database_url, credential, settings.database_token_scope)
        return await _execute(arguments, database)
    finally:
        await credential.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run one repository-token management command."""
    return asyncio.run(_run(_parser().parse_args(argv)))
