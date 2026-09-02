"""Expose the Wheelguard command-line entry point."""

import os

import uvicorn


def main() -> None:
    """Run Wheelguard's HTTP server."""
    uvicorn.run(
        "wheelguard.application:app",
        host=os.getenv("WHEELGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("WHEELGUARD_PORT", "8000")),
    )
