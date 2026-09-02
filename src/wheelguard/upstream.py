"""Retrieve and validate project metadata from an upstream repository."""

from copy import deepcopy
from typing import Any
from urllib.parse import quote, urljoin

import httpx

from wheelguard.models import (
    ProjectResponse,
    SimplePayload,
    UpstreamNotFoundError,
    UpstreamRepositoryError,
)

SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"


class PyPIRepository:
    """Read PEP 691 project metadata from a Python package repository."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize the repository client for an upstream base URL."""
        self._base_url = base_url.rstrip("/") + "/"
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(follow_redirects=True, timeout=timeout_seconds)

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        """Fetch and validate project metadata by normalized name."""
        url = urljoin(self._base_url, f"{quote(normalized_name, safe='')}/")
        try:
            response = await self._client.get(url, headers={"Accept": SIMPLE_JSON})
        except httpx.HTTPError as error:
            raise UpstreamRepositoryError("The upstream repository is unavailable") from error
        if response.status_code == 404:
            raise UpstreamNotFoundError(normalized_name)
        if response.is_error:
            raise UpstreamRepositoryError(f"The upstream repository returned HTTP {response.status_code}")
        try:
            raw: Any = response.json()
        except ValueError as error:
            raise UpstreamRepositoryError("The upstream returned invalid JSON") from error
        if not isinstance(raw, dict) or not isinstance(raw.get("files"), list):
            raise UpstreamRepositoryError("The upstream returned an invalid Simple API payload")

        payload: SimplePayload = deepcopy(raw)
        for file in payload["files"]:
            if not isinstance(file, dict):
                continue
            for field in ("url", "provenance"):
                if isinstance(file.get(field), str):
                    file[field] = urljoin(str(response.url), file[field])
        return ProjectResponse(payload, response.headers.get("X-PyPI-Last-Serial"))

    async def aclose(self) -> None:
        """Close the owned HTTP client."""
        if self._owns_client:
            await self._client.aclose()
