"""Negotiate and render Python Simple Repository API representations."""

from html import escape
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from wheelguard.models import SimplePayload

SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
SIMPLE_HTML = "application/vnd.pypi.simple.v1+html"


def negotiate_content_type(accept: str | None) -> str | None:
    """Select a supported Simple API representation from an Accept header."""
    choices = _parse_accept(accept or "*/*")
    aliases = {
        SIMPLE_JSON: {
            SIMPLE_JSON,
            "application/vnd.pypi.simple.latest+json",
            "application/*",
            "*/*",
        },
        SIMPLE_HTML: {
            SIMPLE_HTML,
            "application/vnd.pypi.simple.latest+html",
            "text/html",
            "text/*",
            "application/*",
            "*/*",
        },
    }
    scored: list[tuple[float, bool, str]] = []
    for preference, media_types in aliases.items():
        for media_type, quality in choices:
            if quality > 0 and media_type in media_types:
                scored.append((quality, preference == SIMPLE_JSON, preference))
                break
    return max(scored)[2] if scored else None


def render_project_html(payload: SimplePayload) -> str:
    """Render project metadata as a PEP 503-compatible HTML page."""
    raw_meta = payload.get("meta")
    meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    name = escape(str(payload.get("name", "")))
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en"><head>',
        f'<meta name="pypi:repository-version" content="{escape(str(meta.get("api-version", "1.0")))}">',
        f"<title>Links for {name}</title>",
        "</head><body>",
        f"<h1>Links for {name}</h1>",
    ]
    files = payload.get("files", [])
    if isinstance(files, list):
        lines.extend(_file_link(file) for file in files if isinstance(file, dict))
    lines.append("</body></html>")
    return "\n".join(lines)


def render_root_html(projects: list[str]) -> str:
    """Render cached project names as a Simple API root page."""
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en"><head>',
        '<meta name="pypi:repository-version" content="1.4">',
        "<title>Wheelguard projects</title>",
        "</head><body>",
    ]
    lines.extend(f'<a href="{escape(project, quote=True)}/">{escape(project)}</a><br>' for project in projects)
    lines.append("</body></html>")
    return "\n".join(lines)


def _file_link(file: dict[str, Any]) -> str:
    filename = escape(str(file.get("filename", "")))
    attributes = [f'href="{escape(_hashed_url(file), quote=True)}"']
    _attribute(attributes, "data-requires-python", file.get("requires-python"))
    yanked = file.get("yanked")
    if yanked is not False and yanked is not None:
        _attribute(attributes, "data-yanked", "" if yanked is True else yanked)
    metadata = file.get("core-metadata")
    _attribute(attributes, "data-core-metadata", _hash_value(metadata) or metadata)
    _attribute(attributes, "data-provenance", file.get("provenance"))
    advisories = file.get("wheelguard-advisories")
    if isinstance(advisories, list):
        _attribute(attributes, "data-wheelguard-advisories", ",".join(map(str, advisories)))
    return f"<a {' '.join(attributes)}>{filename}</a><br>"


def _hashed_url(file: dict[str, Any]) -> str:
    url = str(file.get("url", ""))
    parts = urlsplit(url)
    if parts.fragment:
        return url
    value = _hash_value(file.get("hashes"))
    return urlunsplit((*parts[:4], value or ""))


def _hash_value(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    for algorithm in ("sha256", "sha384", "sha512"):
        digest = value.get(algorithm)
        if isinstance(digest, str):
            return urlencode({algorithm: digest})
    return None


def _attribute(attributes: list[str], name: str, value: object) -> None:
    if value is None or value is False:
        return
    rendered = "true" if value is True else str(value)
    attributes.append(f'{name}="{escape(rendered, quote=True)}"')


def _parse_accept(value: str) -> list[tuple[str, float]]:
    parsed: list[tuple[str, float]] = []
    for item in value.split(","):
        pieces = [piece.strip() for piece in item.split(";")]
        quality = 1.0
        for parameter in pieces[1:]:
            if parameter.startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0.0
        parsed.append((pieces[0].casefold(), quality))
    return parsed
