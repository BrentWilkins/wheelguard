import pytest

from wheelguard.private_service import PrivatePackageService
from wheelguard.project_metadata import project_links


class CatalogDatabase:
    async def private_project_versions(self) -> list[dict[str, str]]:
        return [
            {"normalized_name": "acx-tools", "version": "1.9"},
            {"normalized_name": "flight-kit", "version": "0.8"},
            {"normalized_name": "acx-tools", "version": "1.10"},
        ]


@pytest.mark.anyio
async def test_catalog_returns_each_private_project_with_pep_440_latest_version() -> None:
    service = object.__new__(PrivatePackageService)
    service._database = CatalogDatabase()

    assert await service.catalog() == [("acx-tools", "1.10"), ("flight-kit", "0.8")]


def test_project_links_select_standard_metadata_and_reject_unsafe_urls() -> None:
    assert project_links(
        {
            "project_urls": [
                "Source, https://gitlab.example/acx/demo",
                "Changelog, https://gitlab.example/acx/demo/-/blob/main/CHANGELOG.md",
            ]
        }
    ) == (
        "https://gitlab.example/acx/demo",
        "https://gitlab.example/acx/demo/-/blob/main/CHANGELOG.md",
    )
    assert project_links({"project_urls": ["Changelog, javascript:alert(1)"], "home_page": ["http://example"]}) == (
        None,
        None,
    )
