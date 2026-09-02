"""Verify security properties encoded in the Cloudflare D1 schema."""

import sqlite3
from pathlib import Path

import pytest


def test_policy_audit_is_append_only(tmp_path: Path) -> None:
    """Reject mutation or deletion of an existing policy audit event."""
    connection = sqlite3.connect(tmp_path / "schema.db")
    migrations = Path("migrations")
    connection.executescript((migrations / "0001_cloudflare.sql").read_text())
    connection.executescript((migrations / "0002_immutable_policy_audit.sql").read_text())
    connection.execute(
        """
        INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details)
        VALUES ('audit-1', 'settings.updated', 'admin@example.com', '2026-09-02T00:00:00Z', NULL, '{}')
        """
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE policy_audit SET actor = 'attacker' WHERE id = 'audit-1'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM policy_audit WHERE id = 'audit-1'")
