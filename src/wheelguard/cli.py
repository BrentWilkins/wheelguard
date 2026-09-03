"""Expose the Wheelguard command-line entry point."""

import os
from ipaddress import ip_address

import uvicorn

from wheelguard.auth import configured_tokens


def main() -> None:
    """Run Wheelguard's HTTP server."""
    host = os.getenv("WHEELGUARD_HOST", "127.0.0.1")
    if not _loopback_host(host) and not configured_tokens(
        os.getenv("WHEELGUARD_AUTH_TOKEN"), os.getenv("WHEELGUARD_AUTH_TOKENS")
    ):
        raise SystemExit(
            "WHEELGUARD_AUTH_TOKEN or WHEELGUARD_AUTH_TOKENS is required when listening on a non-loopback address"
        )
    uvicorn.run(
        "wheelguard.application:app",
        host=host,
        port=int(os.getenv("WHEELGUARD_PORT", "8000")),
    )


def _loopback_host(host: str) -> bool:
    """Return whether a bind host is restricted to the local machine."""
    if host.casefold() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False
