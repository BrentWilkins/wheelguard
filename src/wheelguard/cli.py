"""Expose the Wheelguard command-line entry point."""

import os
import sys
from ipaddress import ip_address

import uvicorn

from wheelguard.auth import configured_tokens


def main() -> None:
    """Run Wheelguard's HTTP server."""
    if len(sys.argv) > 1 and sys.argv[1] == "preflight":
        from wheelguard.preflight_cli import main as preflight_main

        raise SystemExit(preflight_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "token":
        from wheelguard.token_cli import main as token_main

        raise SystemExit(token_main(sys.argv[2:]))
    host = os.getenv("WHEELGUARD_HOST", "127.0.0.1")
    private_ingress = os.getenv("WHEELGUARD_TRUST_PRIVATE_INGRESS", "false").casefold() in {"1", "true", "yes", "on"}
    if (
        not _loopback_host(host)
        and not private_ingress
        and not configured_tokens(os.getenv("WHEELGUARD_AUTH_TOKEN"), os.getenv("WHEELGUARD_AUTH_TOKENS"))
    ):
        raise SystemExit(
            "WHEELGUARD_AUTH_TOKEN or WHEELGUARD_AUTH_TOKENS is required when listening on a non-loopback address "
            "unless WHEELGUARD_TRUST_PRIVATE_INGRESS is true"
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
