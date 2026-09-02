"""Test safe self-hosted bind defaults."""

from typing import Any

import pytest

from wheelguard import cli


def test_refuses_unauthenticated_non_loopback_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed instead of exposing an open repository from a container."""
    monkeypatch.setenv("WHEELGUARD_HOST", "0.0.0.0")
    monkeypatch.delenv("WHEELGUARD_AUTH_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="WHEELGUARD_AUTH_TOKEN"):
        cli.main()


def test_allows_unauthenticated_loopback_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep local-only development usable without credentials."""
    called: dict[str, Any] = {}
    monkeypatch.setenv("WHEELGUARD_HOST", "127.0.0.1")
    monkeypatch.delenv("WHEELGUARD_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(cli.uvicorn, "run", lambda *args, **kwargs: called.update(kwargs))
    cli.main()
    assert called["host"] == "127.0.0.1"
