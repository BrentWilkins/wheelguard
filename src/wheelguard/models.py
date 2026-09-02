"""Define shared domain models and structural interfaces."""

from dataclasses import dataclass
from typing import Any, Protocol

type SimplePayload = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ProjectResponse:
    """Represent a project response and its cache metadata."""

    payload: SimplePayload
    last_serial: str | None = None
    cache_status: str = "MISS"


class ProjectRepository(Protocol):
    """Define a source of normalized Simple API project metadata."""

    async def get_project(self, normalized_name: str) -> ProjectResponse:
        """Return metadata for a normalized project name."""
        ...


class UpstreamNotFoundError(Exception):
    """Indicate that an upstream project does not exist."""


class UpstreamRepositoryError(Exception):
    """Indicate that an upstream repository request failed."""


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """Describe a hash-addressed upstream artifact."""

    sha256: str
    filename: str
    source_url: str
    size: int | None = None


class ArtifactNotFoundError(Exception):
    """Indicate that an artifact is absent from the metadata catalog."""


class ArtifactDownloadError(Exception):
    """Indicate that an artifact could not be downloaded or verified."""


@dataclass(frozen=True, slots=True)
class AdvisoryResult:
    """Describe advisory policy output and evaluation status."""

    payload: SimplePayload
    status: str
    vulnerable_files: int = 0


class AdvisoryPolicy(Protocol):
    """Define vulnerability advisory evaluation for project metadata."""

    async def apply(self, project: str, payload: SimplePayload) -> AdvisoryResult:
        """Apply advisory policy to project metadata."""
        ...
