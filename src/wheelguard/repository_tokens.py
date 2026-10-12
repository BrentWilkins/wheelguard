"""Issue opaque repository credentials without persisting their plaintext."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime

OPAQUE_PREFIX = "wg_"


@dataclass(frozen=True, slots=True)
class RepositoryTokenRecord:
    """Describe a repository token without exposing its credential."""

    name: str
    created_at: datetime
    created_by: str
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None


def issue_repository_token() -> str:
    """Create a high-entropy repository token suitable for one-time display."""
    return OPAQUE_PREFIX + secrets.token_urlsafe(32)


def repository_token_digest(token: str) -> bytes:
    """Return the non-reversible lookup digest stored by Wheelguard."""
    return hashlib.sha256(token.encode()).digest()
