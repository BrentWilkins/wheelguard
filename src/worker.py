"""Expose Wheelguard's entrypoint to the Cloudflare Python module loader."""

from wheelguard.worker import Default

__all__ = ["Default"]
