"""Select safe human-facing links from standard Python project metadata."""

from urllib.parse import urlsplit


def project_links(fields: dict[str, list[str]]) -> tuple[str | None, str | None]:
    """Select safe repository and changelog links from standard upload metadata."""
    links: dict[str, str] = {}
    for value in fields.get("project_urls", []):
        label, separator, url = value.partition(",")
        if separator:
            links[label.strip().casefold()] = url.strip()
    home_pages = fields.get("home_page", [])
    repository = next(
        (links[label] for label in ("repository", "source", "source code", "homepage") if label in links),
        home_pages[0].strip() if len(home_pages) == 1 else None,
    )
    changelog = next(
        (links[label] for label in ("changelog", "changes", "release notes") if label in links),
        None,
    )
    return _safe_project_url(repository), _safe_project_url(changelog)


def _safe_project_url(value: str | None) -> str | None:
    """Accept bounded public HTTPS links without embedded credentials."""
    if value is None or len(value) > 2048:
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return value
