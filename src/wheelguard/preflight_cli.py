# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Warm every registry dependency represented by a uv lockfile."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tomllib
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


def main(arguments: list[str] | None = None) -> int:
    """Submit registry packages from a uv lockfile to Wheelguard preflight."""
    parser = argparse.ArgumentParser(prog="wheelguard-preflight")
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"), help="uv lockfile to inspect")
    parser.add_argument("--index-url", required=True, help="Wheelguard index URL, normally ending in /simple/")
    parser.add_argument("--timeout", type=float, default=120.0, help="request timeout in seconds")
    options = parser.parse_args(arguments)

    try:
        packages = projects_from_uv_lock(options.lock)
        endpoint, embedded_token = _endpoint(options.index_url)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        parser.error(str(error))
    token = os.getenv("WHEELGUARD_TOKEN") or os.getenv("UV_INDEX_WHEELGUARD_PASSWORD") or embedded_token
    body = json.dumps({"projects": packages}, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        credentials = base64.b64encode(f"wheelguard:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    request = Request(endpoint, data=body, headers=headers, method="POST")
    try:
        # The endpoint parser above permits HTTPS only.
        with urlopen(request, timeout=options.timeout) as response:  # nosec B310
            result: Any = json.load(response)
    except HTTPError as error:
        try:
            result = json.load(error)
        except (json.JSONDecodeError, UnicodeDecodeError):
            result = {"detail": f"Wheelguard returned HTTP {error.code}"}
        _print_result(result)
        return 3 if error.code >= 500 else 2
    except URLError as error:
        print(f"Wheelguard preflight unavailable: {error.reason}", file=sys.stderr)
        return 3
    _print_result(result)
    return 0


def projects_from_uv_lock(path: Path) -> list[dict[str, object]]:
    """Extract normalized registry names and versions without trusting artifact data."""
    with path.open("rb") as lockfile:
        raw = tomllib.load(lockfile)
    entries = raw.get("package")
    if not isinstance(entries, list):
        raise ValueError(f"{path} does not contain uv package entries")
    projects: dict[str, set[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        name = entry.get("name")
        version = entry.get("version")
        if (
            not isinstance(source, dict)
            or not isinstance(source.get("registry"), str)
            or not isinstance(name, str)
            or not isinstance(version, str)
        ):
            continue
        projects.setdefault(name, set()).add(version)
    if not projects:
        raise ValueError(f"{path} contains no registry packages")
    return [{"name": name, "versions": sorted(versions)} for name, versions in sorted(projects.items())]


def _endpoint(index_url: str) -> tuple[str, str | None]:
    parsed = urlsplit(index_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("--index-url must be an HTTPS Wheelguard URL without a query or fragment")
    path = parsed.path.rstrip("/")
    if path.endswith("/simple"):
        path = path[: -len("/simple")]
    endpoint = urlunsplit(
        (parsed.scheme, parsed.hostname + (f":{parsed.port}" if parsed.port else ""), f"{path}/preflight", "", "")
    )
    return endpoint, parsed.password


def _print_result(result: object) -> None:
    """Print a stable non-secret summary suitable for CI logs."""
    if not isinstance(result, dict):
        print("Wheelguard returned an invalid preflight response", file=sys.stderr)
        return
    status = result.get("status", "ERROR")
    projects = result.get("projects", [])
    counts: dict[str, int] = {}
    if isinstance(projects, list):
        for project in projects:
            if isinstance(project, dict):
                project_status = str(project.get("status", "ERROR"))
                counts[project_status] = counts.get(project_status, 0) + 1
                if project_status != "READY":
                    print(f"{project.get('project', '<unknown>')}: {project_status}", file=sys.stderr)
    summary = " ".join(f"{key.lower()}={value}" for key, value in sorted(counts.items()))
    print(f"preflight={status} projects={len(projects) if isinstance(projects, list) else 0} {summary}".rstrip())


if __name__ == "__main__":
    raise SystemExit(main())
